use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub(super) fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| {
        log::error!("Mutex poisoned, recovering");
        poisoned.into_inner()
    })
}

pub(super) fn read_or_recover<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| {
        log::error!("RwLock read poisoned, recovering");
        poisoned.into_inner()
    })
}

pub(super) fn write_or_recover<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|poisoned| {
        log::error!("RwLock write poisoned, recovering");
        poisoned.into_inner()
    })
}
