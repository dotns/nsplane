//! The drop reasons of [`Redirect`](crate::Redirect).

/// The decision closure answered [`RedirectDecision::Drop`](crate::RedirectDecision::Drop)
/// for a new flow.
pub const DENIED: &str = "redirect denied";
/// Every endpoint the decision closure offered for a new flow (32 in a row,
/// or as set by [`Redirect::with_endpoint_tries`](crate::Redirect::with_endpoint_tries))
/// is in use by a live flow from the same source, so replies could not be
/// told apart.
pub const ENDPOINT_EXHAUSTED: &str = "redirect endpoints exhausted";
/// A new flow could not be recorded: the conntrack table holds no flows at
/// all (`max_entries` is 0).
pub const CONNTRACK_FULL: &str = "redirect conntrack full";
/// A packet of a redirected flow could not be rewritten (its transport
/// header is truncated).
pub const MALFORMED: &str = "redirect malformed";
