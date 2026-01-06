use crossbeam_channel::{unbounded, Sender};

pub struct BackgroundWorker {
    tx: Sender<Box<dyn FnOnce() + Send + 'static>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl BackgroundWorker {
    pub fn new(name: &'static str) -> Self {
        let (tx, rx) = unbounded::<Box<dyn FnOnce() + Send + 'static>>();

        let builder = std::thread::Builder::new().name(name.to_string());
        let handle = builder
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    job();
                }
            })
            .ok();

        Self { tx, handle }
    }

    pub fn spawn<F>(&self, job: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let _ = self.tx.send(Box::new(job));
    }
}

impl Drop for BackgroundWorker {
    fn drop(&mut self) {
        // Dropping the sender closes the queue; worker exits its recv loop.
        self.tx = unbounded::<Box<dyn FnOnce() + Send + 'static>>().0;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;

    #[test]
    fn background_worker_executes_job() {
        let (tx, rx) = crossbeam_channel::bounded::<u32>(1);

        let worker = BackgroundWorker::new("bg-worker-test");
        worker.spawn(move || {
            let _ = tx.send(123);
        });

        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), 123);
    }

    #[test]
    fn background_worker_drop_joins_cleanly() {
        let (tx, rx) = crossbeam_channel::bounded::<()>(1);

        {
            let worker = BackgroundWorker::new("bg-worker-drop-test");
            worker.spawn(move || {
                let _ = tx.send(());
            });
            // Ensure the job ran before Drop (so join won't wait on it).
            rx.recv_timeout(Duration::from_secs(2)).unwrap();
        }
    }

    #[test]
    fn background_worker_runs_all_enqueued_jobs_before_drop() {
        const N: usize = 64;

        let count = Arc::new(AtomicUsize::new(0));
        let worker = BackgroundWorker::new("bg-worker-njobs-test");
        for _ in 0..N {
            let count = Arc::clone(&count);
            worker.spawn(move || {
                count.fetch_add(1, Ordering::SeqCst);
            });
        }

        drop(worker);
        assert_eq!(count.load(Ordering::SeqCst), N);
    }
}
