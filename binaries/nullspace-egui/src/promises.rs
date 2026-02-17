use std::time::{Duration, Instant};

use parking_lot::Mutex;
use poll_promise::Promise;

pub struct PromiseSlot<T: Clone + Send + 'static> {
    inner: Mutex<PromiseState<T>>,
}

enum PromiseState<T: Send + 'static> {
    Idle,
    Running(Promise<T>),
    Ready(T),
}

impl<T: Clone + Send + 'static> PromiseSlot<T> {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(PromiseState::Idle),
        }
    }

    pub fn start(&self, promise: Promise<T>) -> bool {
        let mut guard = self.inner.lock();
        match &*guard {
            PromiseState::Running(_) => false,
            _ => {
                *guard = PromiseState::Running(promise);
                true
            }
        }
    }

    pub fn poll(&self) -> Option<T> {
        let mut guard = self.inner.lock();
        match &mut *guard {
            PromiseState::Idle => None,
            PromiseState::Ready(value) => Some(value.clone()),
            PromiseState::Running(promise) => {
                let value = promise.ready()?.clone();
                *guard = PromiseState::Ready(value.clone());
                Some(value)
            }
        }
    }

    pub fn poll_timeout(&self, timeout: Duration) -> Option<T> {
        let start = Instant::now();
        while start.elapsed() < timeout && self.is_running() {
            let x = self.poll();
            if x.is_some() {
                return x;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        return None;
    }

    pub fn take(&self) -> Option<T> {
        let mut guard = self.inner.lock();
        match &mut *guard {
            PromiseState::Idle => None,
            PromiseState::Ready(_) => {
                let PromiseState::Ready(value) = std::mem::replace(&mut *guard, PromiseState::Idle)
                else {
                    return None;
                };
                Some(value)
            }
            PromiseState::Running(promise) => {
                let value = promise.ready()?.clone();
                *guard = PromiseState::Idle;
                Some(value)
            }
        }
    }

    pub fn is_running(&self) -> bool {
        let guard = self.inner.lock();
        matches!(&*guard, PromiseState::Running(_))
    }

    pub fn is_idle(&self) -> bool {
        let guard = self.inner.lock();
        matches!(&*guard, PromiseState::Idle)
    }
}

pub fn flatten_rpc<T, E>(
    result: Result<Result<T, nullspace_client::internal::InternalRpcError>, E>,
) -> Result<T, String>
where
    E: std::fmt::Display,
{
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(err.to_string()),
        Err(err) => Err(err.to_string()),
    }
}
