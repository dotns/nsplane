//! Result lines on stdout.
//!
//! Examples print machine-readable lines (`CHECK ...`, `CHECKS PASS`, `EVENT ...`) on stdout
//! and log everything else through `tracing` to stderr.

use std::fmt;
use std::io::{self, Write as _};

/// Prints one line to stdout.
///
/// A closed stdout is ignored: the lines are a report, not the example's work.
///
/// ```
/// nsplane_examples::out::line(format_args!("CHECKS {}", "PASS"));
/// ```
pub fn line(args: fmt::Arguments<'_>) {
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{args}");
    let _ = stdout.flush();
}
