// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! epoll-based event loop for Linux.
#![allow(unsafe_code, reason = "epoll, eventfd, timerfd and signalfd syscalls")]

use super::Error;
use libc::{
    CLOCK_BOOTTIME, CLOCK_MONOTONIC, EFD_NONBLOCK, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
    EPOLLET, EPOLLHUP, EPOLLIN, EPOLLONESHOT, EPOLLOUT, SFD_NONBLOCK, SIG_BLOCK, TFD_NONBLOCK,
    c_int, close, epoll_create, epoll_ctl, epoll_event, epoll_wait, eventfd, itimerspec, read,
    sigaddset, sigemptyset, signalfd, sigprocmask, sigset_t, timerfd_create, timerfd_settime,
    timespec, write,
};
use parking_lot::Mutex;
use std::io;
use std::ops::Deref;
use std::os::unix::io::RawFd;
use std::ptr::null_mut;
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
    events: Mutex<Vec<Option<Box<Event<H>>>>>,
    epoll: RawFd, // The OS epoll
}

/// A type that hold a reference to a triggered Event.
///
/// While an `EventGuard` exists for a given Event, it will not be triggered by any other thread
/// Once the `EventGuard` goes out of scope, the underlying Event will be re-enabled
#[derive(Debug)]
pub struct EventGuard<'a, H> {
    epoll: RawFd,
    event: &'a mut Event<H>,
    poll: &'a EventPoll<H>,
}

/// A reference to a single event in an `EventPoll`
#[derive(Debug)]
pub struct EventRef {
    trigger: RawFd,
}

#[allow(
    clippy::struct_field_names,
    reason = "`event` is the epoll_event description"
)]
struct Event<H> {
    event: epoll_event, // The epoll event description
    fd: RawFd,          // The associated fd
    handler: H,         // The associated data
    notifier: bool,     // Is a notification event
    needs_read: bool,   // This event needs to be read to be cleared
}

impl<H> std::fmt::Debug for Event<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Event")
            .field("fd", &self.fd)
            .field("notifier", &self.notifier)
            .field("needs_read", &self.needs_read)
            .finish_non_exhaustive()
    }
}

impl<H> Drop for EventPoll<H> {
    fn drop(&mut self) {
        // SAFETY: `self.epoll` is an epoll fd owned by this poll and closed exactly once.
        unsafe { close(self.epoll) };
    }
}

impl<H: Sync + Send> EventPoll<H> {
    /// Create a new event registry
    pub fn new() -> Result<Self, Error> {
        // SAFETY: plain syscall without pointer arguments.
        let epoll = match unsafe { epoll_create(1) } {
            -1 => return Err(Error::EventQueue(io::Error::last_os_error())),
            epoll => epoll,
        };

        Ok(Self {
            events: Mutex::new(vec![]),
            epoll,
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
        let flags = EPOLLIN | EPOLLONESHOT;
        let ev = Event {
            event: epoll_event {
                events: flags.cast_unsigned(),
                u64: 0,
            },
            fd: trigger,
            handler,
            notifier: false,
            needs_read: false,
        };

        self.register_event(ev)
    }

    /// Add and enable a new write event with the factory.
    /// The event is triggered when a Write operation on the provided trigger becomes possible
    /// For TCP sockets it means that the socket was successfully connected
    #[allow(dead_code)]
    pub fn new_write_event(&self, trigger: RawFd, handler: H) -> Result<EventRef, Error> {
        // Create an event descriptor
        let flags = EPOLLOUT | EPOLLET | EPOLLONESHOT;
        let ev = Event {
            event: epoll_event {
                events: flags.cast_unsigned(),
                u64: 0,
            },
            fd: trigger,
            handler,
            notifier: false,
            needs_read: false,
        };

        self.register_event(ev)
    }

    /// Add and enable a new timed event with the factory.
    /// The even will be triggered for the first time after period time, and henceforth triggered
    /// every period time. Period is counted from the moment the appropriate `EventGuard` is released.
    pub fn new_periodic_event(&self, handler: H, period: Duration) -> Result<EventRef, Error> {
        // The periodic event on Linux uses the timerfd
        // SAFETY: plain syscalls without pointer arguments.
        let tfd = match unsafe { timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK) } {
            // SAFETY: as above.
            -1 => match unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK) } {
                // A fallback for kernels < 3.15
                -1 => return Err(Error::Timer(io::Error::last_os_error())),
                efd => efd,
            },
            efd => efd,
        };

        let ts = timespec {
            tv_sec: libc::time_t::try_from(period.as_secs()).unwrap_or(libc::time_t::MAX),
            tv_nsec: i64::from(period.subsec_nanos()) as _,
        };

        let spec = itimerspec {
            it_value: ts,
            it_interval: ts,
        };

        // SAFETY: `spec` is a valid itimerspec; a NULL old value is allowed.
        if unsafe { timerfd_settime(tfd, 0, &raw const spec, std::ptr::null_mut()) } == -1 {
            // SAFETY: `tfd` was created above and is not registered anywhere.
            unsafe { close(tfd) };
            return Err(Error::Timer(io::Error::last_os_error()));
        }

        let ev = Event {
            event: epoll_event {
                events: (EPOLLIN | EPOLLONESHOT).cast_unsigned(),
                u64: 0,
            },
            fd: tfd,
            handler,
            notifier: false,
            needs_read: true,
        };

        self.register_event(ev)
    }

    /// Add and enable a new notification event with the factory.
    /// The event can only be triggered manually, using the `trigger_notification` method.
    /// The event will remain in a triggered state until the `stop_notification` method is
    /// called. Both methods should only be called with the producing `EventPoll`.
    pub fn new_notifier(&self, handler: H) -> Result<EventRef, Error> {
        // The notifier on Linux uses the eventfd for notifications.
        // The way it works is when a non zero value is written into the eventfd it will trigger
        // the EPOLLIN event. Since we don't enable ONESHOT it will keep triggering until
        // canceled.
        // When we want to stop the event, we read something once from the file descriptor.
        // SAFETY: plain syscall without pointer arguments.
        let efd = match unsafe { eventfd(0, EFD_NONBLOCK) } {
            -1 => return Err(Error::EventQueue(io::Error::last_os_error())),
            efd => efd,
        };

        let ev = Event {
            event: epoll_event {
                events: EPOLLIN.cast_unsigned(),
                u64: 0,
            },
            fd: efd,
            handler,
            notifier: true,
            needs_read: false,
        };

        self.register_event(ev)
    }

    /// Add and enable a new signal handler
    pub fn new_signal_event(&self, signal: c_int, handler: H) -> Result<EventRef, Error> {
        // SAFETY: `sigset` is a zero-initialized sigset_t that the sig* calls initialize; all
        // pointers refer to it.
        let sfd = match unsafe {
            let mut sigset = std::mem::zeroed();
            sigemptyset(&raw mut sigset);
            sigaddset(&raw mut sigset, signal);
            sigprocmask(SIG_BLOCK, &raw const sigset, null_mut());
            signalfd(-1, &raw const sigset, SFD_NONBLOCK)
        } {
            -1 => return Err(Error::EventQueue(io::Error::last_os_error())),
            sfd => sfd,
        };

        let ev = Event {
            event: epoll_event {
                events: (EPOLLIN | EPOLLONESHOT).cast_unsigned(),
                u64: 0,
            },
            fd: sfd,
            handler,
            notifier: false,
            needs_read: true,
        };

        self.register_event(ev)
    }

    /// Wait until one of the registered events becomes triggered. Once an event
    /// is triggered, a single caller thread gets the handler for that event.
    /// In case a notifier is triggered, all waiting threads will receive the same
    /// handler.
    pub fn wait(&self) -> WaitResult<'_, H> {
        let mut event = epoll_event { events: 0, u64: 0 };
        // SAFETY: `event` is a valid buffer for exactly one epoll_event.
        match unsafe { epoll_wait(self.epoll, &raw mut event, 1, -1) } {
            -1 => return WaitResult::Error(io::Error::last_os_error().to_string()),
            1 => {}
            _ => return WaitResult::Error("unexpected number of events returned".to_string()),
        }

        // SAFETY: `u64` holds the address of a boxed `Event<H>` registered in `self.events`.
        // The box stays alive until the event is cleared, and EPOLLONESHOT guarantees that only
        // this thread holds the event until the guard re-arms it.
        let Some(event_data) = (unsafe { (event.u64 as *mut Event<H>).as_mut() }) else {
            return WaitResult::Error("epoll returned an event without data".to_string());
        };

        let guard = EventGuard {
            epoll: self.epoll,
            event: event_data,
            poll: self,
        };

        if event.events & EPOLLHUP.cast_unsigned() != 0 {
            // End of file flag
            WaitResult::EoF(guard)
        } else {
            WaitResult::Ok(guard)
        }
    }

    // Register an event with this poll.
    fn register_event(&self, ev: Event<H>) -> Result<EventRef, Error> {
        // To register an event we
        // * Create a reference to self in the inner event
        // * Store the Event in the events vector
        // * Dispose of a previous Event under same fd if any
        // * Add the Event to epoll
        let trigger = ev.fd;
        let mut ev = Box::new(ev);
        // The inner event points back to the wrapper
        ev.event.u64 = std::ptr::from_mut::<Event<H>>(ev.as_mut()) as _;
        let mut event_desc = ev.event;
        // Now add the pointer to the events vector, this is a place from which we can drop the event
        let Ok(index) = usize::try_from(trigger) else {
            return Err(Error::EventQueue(io::Error::from_raw_os_error(libc::EBADF)));
        };
        self.insert_at(index, ev);
        // Add the event to epoll
        // SAFETY: `event_desc` is a valid epoll_event for the duration of the call.
        if unsafe { epoll_ctl(self.epoll, EPOLL_CTL_ADD, trigger, &raw mut event_desc) } == -1 {
            return Err(Error::EventQueue(io::Error::last_os_error()));
        }

        Ok(EventRef { trigger })
    }

    // Insert an event into the events vector
    fn insert_at(&self, index: usize, data: Box<Event<H>>) {
        let mut events = self.events.lock();
        while events.len() <= index {
            // Resize the vector to be able to fit the new index
            // We trust the OS to allocate file descriptors in a sane order
            events.push(None); // resize doesn't work because Clone is not satisfied
        }

        if events[index].take().is_some() {
            // Properly remove the previous event first
            if let Ok(fd) = RawFd::try_from(index) {
                // SAFETY: EPOLL_CTL_DEL ignores the event pointer.
                unsafe {
                    epoll_ctl(self.epoll, EPOLL_CTL_DEL, fd, null_mut());
                };
            }
        }

        events[index] = Some(data);
    }

    /// Trigger a notification
    pub fn trigger_notification(&self, notification_event: &EventRef) {
        if !self.is_notifier(notification_event) {
            tracing::error!("Can only trigger a notification event");
            return;
        }

        // Write some data to the eventfd to trigger an EPOLLIN event
        let value = (u64::MAX - 1).to_ne_bytes();
        // SAFETY: `value` is a valid 8-byte buffer, as eventfd requires.
        unsafe {
            write(
                notification_event.trigger,
                value.as_ptr().cast(),
                value.len(),
            )
        };
    }

    fn is_notifier(&self, event: &EventRef) -> bool {
        let events = self.events.lock();
        usize::try_from(event.trigger)
            .ok()
            .and_then(|i| events.get(i))
            .and_then(Option::as_ref)
            .is_some_and(|e| e.notifier)
    }

    /// Stop a notification
    pub fn stop_notification(&self, notification_event: &EventRef) {
        if !self.is_notifier(notification_event) {
            tracing::error!("Can only stop a notification event");
            return;
        }

        let mut buf = [0u8; 8];
        // SAFETY: `buf` is a valid 8-byte buffer, as eventfd requires.
        unsafe {
            read(
                notification_event.trigger,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
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
        let mut events = self.events.lock();
        let slot = usize::try_from(index).ok().and_then(|i| events.get_mut(i));
        if slot.and_then(Option::take).is_some() {
            // SAFETY: EPOLL_CTL_DEL ignores the event pointer.
            unsafe { epoll_ctl(self.epoll, EPOLL_CTL_DEL, index, null_mut()) };
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
        if self.event.needs_read {
            // Must read from the event to reset it before we enable it
            let mut buf = [0u8; 256];
            // SAFETY: `buf` is valid for writes of `buf.len()` bytes.
            while unsafe { read(self.event.fd, buf.as_mut_ptr().cast(), buf.len()) } != -1 {}
        }

        // SAFETY: `self.event.event` is a valid epoll_event that lives in the boxed Event.
        unsafe {
            epoll_ctl(
                self.epoll,
                EPOLL_CTL_MOD,
                self.event.fd,
                &raw mut self.event.event,
            );
        }
    }
}

impl<H> EventGuard<'_, H> {
    /// Get a mutable reference to the stored value
    #[allow(dead_code)]
    pub const fn get_mut(&mut self) -> &mut H {
        &mut self.event.handler
    }

    /// Cancel and remove the event referenced by this guard
    pub fn cancel(self) {
        // SAFETY: the guard is the only holder of this event (EPOLLONESHOT), so no other
        // thread can be running its handler while it is freed.
        unsafe { self.poll.clear_event_by_fd(self.event.fd) };
        std::mem::forget(self); // Don't call the regular drop that would enable the event
    }

    /// The fd the triggered event was registered for.
    pub const fn fd(&self) -> i32 {
        self.event.fd
    }

    /// Change the event flags to enable or disable notifying when the fd is writable
    pub const fn notify_writable(&mut self, enabled: bool) {
        let flags = if enabled {
            EPOLLOUT | EPOLLIN | EPOLLET | EPOLLONESHOT
        } else {
            EPOLLIN | EPOLLONESHOT
        };
        self.event.event.events = flags.cast_unsigned();
    }
}

/// Blocks `signal` for the calling thread and returns the signal set.
pub fn block_signal(signal: c_int) -> Result<sigset_t, String> {
    // SAFETY: `sigset` is zero-initialized and then initialized by sigemptyset; all pointers
    // refer to it.
    unsafe {
        let mut sigset = std::mem::zeroed();
        sigemptyset(&raw mut sigset);
        if sigaddset(&raw mut sigset, signal) == -1 {
            return Err(io::Error::last_os_error().to_string());
        }
        if sigprocmask(SIG_BLOCK, &raw const sigset, null_mut()) == -1 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(sigset)
    }
}
