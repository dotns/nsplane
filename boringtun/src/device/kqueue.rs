// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! kqueue-based event loop for macOS, iOS and tvOS.
#![allow(unsafe_code, reason = "kqueue syscalls")]

use super::Error;
use libc::{
    EV_ADD, EV_DELETE, EV_DISABLE, EV_DISPATCH, EV_ENABLE, EV_EOF, EVFILT_READ, EVFILT_SIGNAL,
    EVFILT_TIMER, EVFILT_USER, NOTE_NSECONDS, NOTE_TRIGGER, SIG_IGN, c_int, close, kevent, kqueue,
    signal,
};
use parking_lot::Mutex;
use std::io;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::ptr::{null, null_mut};
use std::time::Duration;

/// A return type for the `EventPoll::wait()` function
#[derive(Debug)]
pub enum WaitResult<'a, H> {
    /// Event triggered normally
    Ok(EventGuard<'a, H>),
    /// Event triggered due to End of File conditions
    EoF(EventGuard<'a, H>),
    /// There was an error
    Error(String),
}

/// Implements a registry of pollable events
#[derive(Debug)]
pub struct EventPoll<H: Sized> {
    events: Mutex<Vec<Option<Box<Event<H>>>>>, // Events with a file descriptor
    custom: Mutex<Vec<Option<Box<Event<H>>>>>, // Other events (i.e. timers & notifiers)
    signals: Mutex<Vec<Option<Box<Event<H>>>>>, // Signal handlers
    kqueue: RawFd,                             // The OS kqueue
}

/// A type that hold a reference to a triggered Event.
///
/// While an `EventGuard` exists for a given Event, it will not be triggered by any other thread
/// Once the `EventGuard` goes out of scope, the underlying Event will be re-enabled
#[derive(Debug)]
pub struct EventGuard<'a, H> {
    kqueue: RawFd,
    event: &'a Event<H>,
    poll: &'a EventPoll<H>,
}

/// A reference to a single event in an `EventPoll`
#[derive(Debug)]
pub struct EventRef {
    trigger: RawFd,
}

#[derive(PartialEq, Eq, Debug)]
enum EventKind {
    Fd,
    Notifier,
    Signal,
    Timer,
}

// A single event
#[allow(
    clippy::struct_field_names,
    reason = "`event` is the kevent description"
)]
struct Event<H> {
    event: kevent, // The kqueue event description
    handler: H,    // The associated data
    kind: EventKind,
}

impl<H> std::fmt::Debug for Event<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Event")
            .field("ident", &{ self.event.ident })
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl<H> Drop for EventPoll<H> {
    fn drop(&mut self) {
        // SAFETY: `self.kqueue` is owned by this poll and closed exactly once.
        unsafe { close(self.kqueue) };
    }
}

// SAFETY: the raw `udata` pointers inside `kevent` only point into boxes owned by this poll;
// all access to the event tables goes through the mutexes, and EV_DISPATCH hands each event
// to a single thread at a time.
#[allow(clippy::non_send_fields_in_send_ty, reason = "see SAFETY")]
unsafe impl<H: Send> Send for EventPoll<H> {}
// SAFETY: see `Send` above.
unsafe impl<H: Send + Sync> Sync for EventPoll<H> {}

/// An empty `kevent` with the given identity.
const fn kev(ident: usize, filter: i16, flags: u16, fflags: u32, data: isize) -> kevent {
    kevent {
        ident,
        filter,
        flags,
        fflags,
        data,
        udata: null_mut(),
    }
}

/// Applies a single change to `kq`.
fn kevent_apply(kq: RawFd, change: &kevent) -> c_int {
    // SAFETY: `change` is a valid kevent; no events are requested back.
    unsafe { kevent(kq, change, 1, null_mut(), 0, null()) }
}

impl<H: Send + Sync> EventPoll<H> {
    /// Create a new event registry
    pub fn new() -> Result<Self, Error> {
        // SAFETY: plain syscall without arguments.
        let kqueue = match unsafe { kqueue() } {
            -1 => return Err(Error::EventQueue(io::Error::last_os_error())),
            kqueue => kqueue,
        };

        Ok(Self {
            events: Mutex::new(vec![]),
            custom: Mutex::new(vec![]),
            signals: Mutex::new(vec![]),
            kqueue,
        })
    }

    /// Add and enable a new event with the factory.
    /// The event is triggered when a Read operation on the provided trigger becomes available
    /// If the trigger fd is closed, the event won't be triggered anymore, but it's data won't be
    /// automatically released.
    /// The safe way to delete an event, is using the cancel method of an `EventGuard`.
    /// If the same trigger is used with multiple events in the same `EventPoll`, the last added
    /// event overrides all previous events. In case the same trigger is used with multiple polls,
    /// each event will be triggered independently.
    /// The event will keep triggering until a Read operation is no longer possible on the trigger.
    /// When triggered, one of the threads waiting on the poll will receive the handler via an
    /// appropriate `EventGuard`. It is guaranteed that only a single thread can have a reference to
    /// the handler at any given time.
    pub fn new_event(&self, trigger: RawFd, handler: H) -> Result<EventRef, Error> {
        // Create an event descriptor
        let flags = EV_ENABLE | EV_DISPATCH;

        let Ok(ident) = usize::try_from(trigger) else {
            return Err(Error::EventQueue(io::Error::from_raw_os_error(libc::EBADF)));
        };
        let ev = Event {
            event: kev(ident, EVFILT_READ, flags, 0, 0),
            handler,
            kind: EventKind::Fd,
        };

        self.register_event(ev)
    }

    /// Add and enable a new timed event, triggered every `period`.
    pub fn new_periodic_event(&self, handler: H, period: Duration) -> Result<EventRef, Error> {
        // The periodic event in BSD uses EVFILT_TIMER
        let nanos = isize::try_from(period.as_nanos()).unwrap_or(isize::MAX);
        let ev = Event {
            event: kev(
                0,
                EVFILT_TIMER,
                EV_ENABLE | EV_DISPATCH,
                NOTE_NSECONDS,
                nanos,
            ),
            handler,
            kind: EventKind::Timer,
        };

        self.register_event(ev)
    }

    /// Add and enable a new notification event, triggered with `trigger_notification`.
    pub fn new_notifier(&self, handler: H) -> Result<EventRef, Error> {
        // The notifier in BSD uses EVFILT_USER for notifications.
        let ev = Event {
            event: kev(0, EVFILT_USER, EV_ENABLE, 0, 0),
            handler,
            kind: EventKind::Notifier,
        };

        self.register_event(ev)
    }

    /// Add and enable a new signal handler
    pub fn new_signal_event(&self, signal: c_int, handler: H) -> Result<EventRef, Error> {
        let Ok(ident) = usize::try_from(signal) else {
            return Err(Error::EventQueue(io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        };
        let ev = Event {
            event: kev(ident, EVFILT_SIGNAL, EV_ENABLE | EV_DISPATCH, 0, 0),
            handler,
            kind: EventKind::Signal,
        };

        self.register_event(ev)
    }

    /// Wait until one of the registered events becomes triggered. Once an event
    /// is triggered, a single caller thread gets the handler for that event.
    /// In case a notifier is triggered, all waiting threads will receive the same
    /// handler.
    pub fn wait(&self) -> WaitResult<'_, H> {
        let mut event = kev(0, 0, 0, 0, 0);

        // SAFETY: `event` is a valid buffer for exactly one kevent.
        if unsafe { kevent(self.kqueue, null(), 0, &raw mut event, 1, null()) } == -1 {
            return WaitResult::Error(io::Error::last_os_error().to_string());
        }

        // SAFETY: `udata` holds the address of a boxed `Event<H>` owned by this poll. The box
        // lives until the event is cleared, and EV_DISPATCH hands it to this thread only.
        let Some(event_data) = (unsafe { event.udata.cast::<Event<H>>().as_ref() }) else {
            return WaitResult::Error("kqueue returned an event without data".to_string());
        };

        let guard = EventGuard {
            kqueue: self.kqueue,
            event: event_data,
            poll: self,
        };

        if event.flags & EV_EOF != 0 {
            WaitResult::EoF(guard)
        } else {
            WaitResult::Ok(guard)
        }
    }

    // Register an event with this poll.
    fn register_event(&self, ev: Event<H>) -> Result<EventRef, Error> {
        let mut events = match ev.kind {
            EventKind::Fd => self.events.lock(),
            EventKind::Timer | EventKind::Notifier => self.custom.lock(),
            EventKind::Signal => self.signals.lock(),
        };

        let (trigger, index) = match ev.kind {
            EventKind::Fd | EventKind::Signal => (
                RawFd::try_from(ev.event.ident).unwrap_or(RawFd::MAX),
                ev.event.ident,
            ),
            // Custom events get negative identifiers, hopefully we will never have more than
            // 2^31 events of each type
            EventKind::Timer | EventKind::Notifier => (
                -RawFd::try_from(events.len()).unwrap_or(RawFd::MAX) - 1,
                events.len(),
            ),
        };

        // Expand events vector if needed
        while events.len() <= index {
            // Resize the vector to be able to fit the new index
            // We trust the OS to allocate file descriptors in a sane order
            events.push(None); // resize doesn't work because Clone is not satisfied
        }

        let mut ev = Box::new(ev);
        // The inner event points back to the wrapper
        // Custom events are identified by their (negative) trigger, reinterpreted as usize.
        #[allow(
            clippy::cast_sign_loss,
            reason = "round trip, see `EventGuard::cancel`"
        )]
        let ident = trigger as usize;
        ev.event.ident = ident;
        ev.event.udata = std::ptr::from_mut::<Event<H>>(ev.as_mut()).cast();

        let mut change = ev.event;
        change.flags |= EV_ADD;

        if kevent_apply(self.kqueue, &change) == -1 {
            return Err(Error::EventQueue(io::Error::last_os_error()));
        }

        if let Some(mut event) = events[index].take() {
            // Properly remove any previous event first
            event.event.flags = EV_DELETE;
            kevent_apply(self.kqueue, &event.event);
        }

        if ev.kind == EventKind::Signal {
            // Mask the signal if successfully added to kqueue
            // SAFETY: ignoring a signal installs no handler code.
            unsafe { signal(trigger, SIG_IGN) };
        }

        events[index] = Some(ev);

        Ok(EventRef { trigger })
    }

    /// The kevent of the notifier behind `event`, if it is one.
    fn notifier_event(&self, event: &EventRef) -> Option<kevent> {
        let events = self.custom.lock();
        // Custom events have negative index from -1
        let index = usize::try_from(-event.trigger - 1).ok()?;
        events
            .get(index)?
            .as_ref()
            .filter(|e| e.kind == EventKind::Notifier)
            .map(|e| e.event)
    }

    /// Trigger a notification
    pub fn trigger_notification(&self, notification_event: &EventRef) {
        let Some(mut change) = self.notifier_event(notification_event) else {
            tracing::error!("Can only trigger a notification event");
            return;
        };
        change.fflags = NOTE_TRIGGER;
        kevent_apply(self.kqueue, &change);
    }

    /// Stop a notification
    pub fn stop_notification(&self, notification_event: &EventRef) {
        let Some(mut change) = self.notifier_event(notification_event) else {
            tracing::error!("Can only stop a notification event");
            return;
        };
        change.flags = EV_DISABLE;
        change.fflags = 0;
        kevent_apply(self.kqueue, &change);
    }
}

impl<H> EventPoll<H> {
    /// Disable and remove the event and associated handler, using the fd that
    /// was used to register it.
    ///
    /// # Safety
    ///
    /// This function is only safe to call when the event loop is not running,
    /// otherwise the memory of the handler may get freed while in use.
    pub unsafe fn clear_event_by_fd(&self, index: RawFd) {
        let (mut events, index) = if index >= 0 {
            (self.events.lock(), usize::try_from(index).ok())
        } else {
            (self.custom.lock(), usize::try_from(-index - 1).ok())
        };

        if let Some(mut event) = index.and_then(|i| events.get_mut(i)).and_then(Option::take) {
            // Properly remove any previous event first
            event.event.flags = EV_DELETE;
            kevent_apply(self.kqueue, &event.event);
        }
    }
}

impl<H> Deref for EventGuard<'_, H> {
    type Target = H;
    fn deref(&self) -> &H {
        &self.event.handler
    }
}

impl<H> Drop for EventGuard<'_, H> {
    fn drop(&mut self) {
        // Re-enable the event once EventGuard goes out of scope
        kevent_apply(self.kqueue, &self.event.event);
    }
}

impl<H> EventGuard<'_, H> {
    /// Cancel and remove the event represented by this guard
    pub fn cancel(self) {
        // Custom events store their negative trigger reinterpreted as usize.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_possible_wrap,
            reason = "round trip"
        )]
        let trigger = self.event.event.ident as RawFd;
        // SAFETY: the guard is the only holder of this event (EV_DISPATCH), so no other
        // thread can be running its handler while it is freed.
        unsafe { self.poll.clear_event_by_fd(trigger) };
        std::mem::forget(self); // Don't call the regular drop that would enable the event
    }

    /// Stub: only used for Linux-specific features.
    pub const fn fd(&self) -> i32 {
        -1
    }
}
