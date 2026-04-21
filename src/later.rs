use chrono::{DateTime, Utc};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type SleepFn = dyn Fn(Duration) -> BoxFuture + Send + Sync;
type NowFn = dyn Fn() -> DateTime<Utc> + Send + Sync;

pub trait Do: Send + 'static {
    fn run(self: Box<Self>) -> BoxFuture;
}

impl<F, Fut> Do for F
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn run(self: Box<Self>) -> BoxFuture {
        Box::pin((*self)())
    }
}

#[derive(Clone)]
pub struct LaterService {
    inner: Arc<LaterState>,
}

struct LaterState {
    scheduled: Mutex<ScheduledCallbacks>,
    wake_worker: Notify,
    now: Arc<NowFn>,
    sleep: Arc<SleepFn>,
}

#[derive(Default)]
struct ScheduledCallbacks {
    callbacks: Vec<ScheduledCallback>,
    worker_running: bool,
}

struct ScheduledCallback {
    run_at: DateTime<Utc>,
    callback: Box<dyn Do>,
}

impl LaterService {
    pub fn new() -> Self {
        Self::with_implementations(Utc::now, |duration| async move {
            tokio::time::sleep(duration).await;
        })
    }

    pub fn with_implementations<Now, Sleep, SleepFuture>(now: Now, sleep: Sleep) -> Self
    where
        Now: Fn() -> DateTime<Utc> + Send + Sync + 'static,
        Sleep: Fn(Duration) -> SleepFuture + Send + Sync + 'static,
        SleepFuture: Future<Output = ()> + Send + 'static,
    {
        Self {
            inner: Arc::new(LaterState {
                scheduled: Mutex::new(ScheduledCallbacks::default()),
                wake_worker: Notify::new(),
                now: Arc::new(now),
                sleep: Arc::new(move |duration| Box::pin(sleep(duration))),
            }),
        }
    }

    pub fn later(&self, callback: impl Do, delay: Duration) {
        let run_at = self.now() + chrono::Duration::from_std(delay).unwrap();
        let should_spawn_worker = {
            let mut scheduled = self.inner.scheduled.lock().unwrap();
            scheduled.callbacks.push(ScheduledCallback {
                run_at,
                callback: Box::new(callback),
            });

            if scheduled.worker_running {
                false
            } else {
                scheduled.worker_running = true;
                true
            }
        };

        if should_spawn_worker {
            let later = self.clone();
            tokio::spawn(async move {
                later.run().await;
            });
        }

        self.inner.wake_worker.notify_one();
    }

    async fn run(self) {
        loop {
            let Some(next_run_at) = self.next_run_at() else {
                return;
            };

            let sleep_duration = duration_until(self.now(), next_run_at);
            if !sleep_duration.is_zero() {
                tokio::select! {
                    _ = self.sleep(sleep_duration) => {}
                    _ = self.inner.wake_worker.notified() => {
                        continue;
                    }
                }
            }

            let now = self.now();
            if now < next_run_at {
                continue;
            }

            let due_callbacks = self.take_due_callbacks(now);
            for callback in due_callbacks {
                callback.run().await;
            }
        }
    }

    fn next_run_at(&self) -> Option<DateTime<Utc>> {
        let mut scheduled = self.inner.scheduled.lock().unwrap();
        if scheduled.callbacks.is_empty() {
            scheduled.worker_running = false;
            return None;
        }

        scheduled
            .callbacks
            .iter()
            .map(|callback| callback.run_at)
            .min()
    }

    fn take_due_callbacks(&self, now: DateTime<Utc>) -> Vec<Box<dyn Do>> {
        let mut scheduled = self.inner.scheduled.lock().unwrap();
        let mut due = Vec::new();
        let mut pending = Vec::with_capacity(scheduled.callbacks.len());

        for callback in scheduled.callbacks.drain(..) {
            if callback.run_at <= now {
                due.push(callback.callback);
            } else {
                pending.push(callback);
            }
        }

        scheduled.callbacks = pending;
        due
    }

    fn now(&self) -> DateTime<Utc> {
        (self.inner.now)()
    }

    fn sleep(&self, duration: Duration) -> BoxFuture {
        (self.inner.sleep)(duration)
    }
}

fn duration_until(now: DateTime<Utc>, target: DateTime<Utc>) -> Duration {
    (target - now).to_std().unwrap_or(Duration::ZERO)
}

#[cfg(test)]
mod tests {
    use super::LaterService;
    use chrono::{TimeZone, Utc};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot};

    #[derive(Clone)]
    struct FakeTime {
        now: Arc<Mutex<chrono::DateTime<Utc>>>,
        sleeps: Arc<Mutex<Vec<Duration>>>,
    }

    impl FakeTime {
        fn new(start: chrono::DateTime<Utc>) -> Self {
            Self {
                now: Arc::new(Mutex::new(start)),
                sleeps: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn later_service(&self) -> LaterService {
            let now = self.clone();
            let sleep = self.clone();
            LaterService::with_implementations(
                move || now.now(),
                move |duration| {
                    let sleep = sleep.clone();
                    async move {
                        sleep.record_sleep(duration);
                        sleep.advance(duration);
                        tokio::task::yield_now().await;
                    }
                },
            )
        }

        fn now(&self) -> chrono::DateTime<Utc> {
            *self.now.lock().unwrap()
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.now.lock().unwrap();
            *now += chrono::Duration::from_std(duration).unwrap();
        }

        fn record_sleep(&self, duration: Duration) {
            self.sleeps.lock().unwrap().push(duration);
        }

        fn sleeps(&self) -> Vec<Duration> {
            self.sleeps.lock().unwrap().clone()
        }
    }

    #[tokio::test]
    async fn later_runs_callback_after_delay() {
        let later = LaterService::new();
        let (tx, rx) = oneshot::channel();

        later.later(
            move || async move {
                let _ = tx.send(());
            },
            Duration::from_millis(10),
        );

        tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("callback timed out")
            .expect("callback dropped");
    }

    #[tokio::test]
    async fn later_wakes_early_for_new_earlier_callback() {
        let later = LaterService::new();
        let order = Arc::new(AtomicUsize::new(0));
        let first = Arc::new(AtomicUsize::new(0));
        let second = Arc::new(AtomicUsize::new(0));

        {
            let order = order.clone();
            let first = first.clone();
            later.later(
                move || async move {
                    first.store(order.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                },
                Duration::from_millis(50),
            );
        }

        tokio::time::sleep(Duration::from_millis(10)).await;

        {
            let order = order.clone();
            let second = second.clone();
            later.later(
                move || async move {
                    second.store(order.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                },
                Duration::from_millis(10),
            );
        }

        tokio::time::sleep(Duration::from_millis(120)).await;

        assert_eq!(second.load(Ordering::SeqCst), 1);
        assert_eq!(first.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn later_uses_provided_now_and_sleep_implementations() {
        let fake_time = FakeTime::new(Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap());
        let later = fake_time.later_service();
        let (tx, rx) = oneshot::channel();

        later.later(
            move || async move {
                let _ = tx.send(());
            },
            Duration::from_secs(5),
        );

        tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("callback timed out")
            .expect("callback dropped");

        assert_eq!(fake_time.sleeps(), vec![Duration::from_secs(5)]);
        assert_eq!(
            fake_time.now(),
            Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 5).unwrap()
        );
    }

    #[tokio::test]
    async fn zero_delay_runs_without_sleeping() {
        let fake_time = FakeTime::new(Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap());
        let later = fake_time.later_service();
        let (tx, rx) = oneshot::channel();

        later.later(
            move || async move {
                let _ = tx.send(());
            },
            Duration::ZERO,
        );

        tokio::time::timeout(Duration::from_secs(1), rx)
            .await
            .expect("callback timed out")
            .expect("callback dropped");

        assert!(fake_time.sleeps().is_empty());
    }

    #[tokio::test]
    async fn multiple_callbacks_run_in_delay_order() {
        let fake_time = FakeTime::new(Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap());
        let later = fake_time.later_service();
        let (tx, mut rx) = mpsc::unbounded_channel();

        for (label, delay) in [
            ("third", Duration::from_secs(30)),
            ("first", Duration::from_secs(10)),
            ("second", Duration::from_secs(20)),
        ] {
            let tx = tx.clone();
            later.later(
                move || async move {
                    let _ = tx.send(label);
                },
                delay,
            );
        }

        let mut seen = Vec::new();
        for _ in 0..3 {
            seen.push(
                tokio::time::timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .expect("callback timed out")
                    .expect("channel closed early"),
            );
        }

        assert_eq!(seen, vec!["first", "second", "third"]);
        assert_eq!(
            fake_time.sleeps(),
            vec![
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_secs(10),
            ]
        );
    }

    #[tokio::test]
    async fn callbacks_with_same_deadline_all_run() {
        let fake_time = FakeTime::new(Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap());
        let later = fake_time.later_service();
        let (tx, mut rx) = mpsc::unbounded_channel();

        for label in ["first", "second", "third"] {
            let tx = tx.clone();
            later.later(
                move || async move {
                    let _ = tx.send(label);
                },
                Duration::from_secs(5),
            );
        }

        let mut seen = Vec::new();
        for _ in 0..3 {
            seen.push(
                tokio::time::timeout(Duration::from_secs(1), rx.recv())
                    .await
                    .expect("callback timed out")
                    .expect("channel closed early"),
            );
        }

        seen.sort_unstable();
        assert_eq!(seen, vec!["first", "second", "third"]);
        assert_eq!(fake_time.sleeps(), vec![Duration::from_secs(5)]);
    }

    #[tokio::test]
    async fn worker_starts_again_after_becoming_idle() {
        let fake_time = FakeTime::new(Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap());
        let later = fake_time.later_service();

        let (first_tx, first_rx) = oneshot::channel();
        later.later(
            move || async move {
                let _ = first_tx.send(());
            },
            Duration::from_secs(3),
        );
        tokio::time::timeout(Duration::from_secs(1), first_rx)
            .await
            .expect("first callback timed out")
            .expect("first callback dropped");

        let (second_tx, second_rx) = oneshot::channel();
        later.later(
            move || async move {
                let _ = second_tx.send(());
            },
            Duration::from_secs(2),
        );
        tokio::time::timeout(Duration::from_secs(1), second_rx)
            .await
            .expect("second callback timed out")
            .expect("second callback dropped");

        assert_eq!(
            fake_time.sleeps(),
            vec![Duration::from_secs(3), Duration::from_secs(2)]
        );
    }

    #[tokio::test]
    async fn callback_can_schedule_follow_up_work() {
        let fake_time = FakeTime::new(Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap());
        let later = fake_time.later_service();
        let (tx, mut rx) = mpsc::unbounded_channel();

        {
            let tx = tx.clone();
            let scheduler = later.clone();
            let callback_scheduler = scheduler.clone();
            scheduler.later(
                move || async move {
                    let _ = tx.send("first");
                    let tx = tx.clone();
                    callback_scheduler.later(
                        move || async move {
                            let _ = tx.send("second");
                        },
                        Duration::from_secs(5),
                    );
                },
                Duration::from_secs(1),
            );
        }

        let first = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("first callback timed out")
            .expect("channel closed early");
        let second = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("second callback timed out")
            .expect("channel closed early");

        assert_eq!((first, second), ("first", "second"));
        assert_eq!(
            fake_time.sleeps(),
            vec![Duration::from_secs(1), Duration::from_secs(5)]
        );
    }

    #[tokio::test]
    async fn long_running_callback_causes_later_due_callback_to_run_immediately_after() {
        let fake_time = FakeTime::new(Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap());
        let later = fake_time.later_service();
        let (tx, mut rx) = mpsc::unbounded_channel();

        {
            let tx = tx.clone();
            let fake_time = fake_time.clone();
            later.later(
                move || async move {
                    let _ = tx.send("first");
                    fake_time.advance(Duration::from_secs(20));
                    tokio::task::yield_now().await;
                },
                Duration::from_secs(10),
            );
        }

        {
            let tx = tx.clone();
            later.later(
                move || async move {
                    let _ = tx.send("second");
                },
                Duration::from_secs(15),
            );
        }

        let first = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("first callback timed out")
            .expect("channel closed early");
        let second = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("second callback timed out")
            .expect("channel closed early");

        assert_eq!((first, second), ("first", "second"));
        assert_eq!(fake_time.sleeps(), vec![Duration::from_secs(10)]);
    }
}
