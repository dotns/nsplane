//! [`StaticRecords`]: a fixed table of local records.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;

use crate::message::{Answer, CLASS_IN, Query, Record, RecordType, ResponseCode, normalize_name};
use crate::resolver::{Fallback, Resolver};

/// A table of records by name, answering from memory.
///
/// Names match case-insensitively, with or without a trailing dot. For a known name of class
/// IN the answer is:
///
/// - its `CNAME` records, whatever the query type, when it has any;
/// - otherwise its records of the query type (all of them for `ANY`);
/// - `NODATA` (an empty [`Answer::Records`]) when it has none of that type.
///
/// Unknown names and other classes answer `NXDOMAIN`, which [`with_fallback`](Self::with_fallback)
/// hands to another resolver. Fill the table with [`insert`](Self::insert) or `collect()`,
/// then share it; resolving is a hash lookup.
#[derive(Debug, Clone, Default)]
pub struct StaticRecords {
    names: HashMap<String, Vec<Record>>,
}

impl StaticRecords {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `record`; its name is normalized (lowercase, no trailing dot).
    pub fn insert(&mut self, mut record: Record) -> &mut Self {
        record.name = normalize_name(&record.name);
        self.names
            .entry(record.name.clone())
            .or_default()
            .push(record);
        self
    }

    /// Number of names in the table.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the table has no names.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Asks `fallback` for the names this table answers `NXDOMAIN`.
    pub const fn with_fallback<R>(self, fallback: R) -> Fallback<Self, R> {
        Fallback::new(self, fallback)
    }

    /// The answer to `query`, as described on the type.
    pub fn lookup(&self, query: &Query) -> Answer {
        let records = match self.names.get(query.name()) {
            Some(records) if query.class() == CLASS_IN => records,
            _ => return Answer::Code(ResponseCode::NxDomain),
        };
        let wanted = query.record_type();
        let has_cname = records.iter().any(|r| r.record_type() == RecordType::CNAME);
        let answers = records
            .iter()
            .filter(|r| {
                let ty = r.record_type();
                if has_cname {
                    ty == RecordType::CNAME
                } else {
                    wanted == RecordType::ANY || ty == wanted
                }
            })
            .cloned()
            .collect();
        Answer::Records(answers)
    }
}

impl FromIterator<Record> for StaticRecords {
    fn from_iter<I: IntoIterator<Item = Record>>(iter: I) -> Self {
        let mut table = Self::new();
        for record in iter {
            table.insert(record);
        }
        table
    }
}

impl Resolver for StaticRecords {
    fn resolve(&self, query: &Query, _client: SocketAddr) -> impl Future<Output = Answer> + Send {
        std::future::ready(self.lookup(query))
    }
}
