use std::{
    io::{Error, ErrorKind},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::Result;

pub const FRAME: Duration = Duration::from_nanos(1_000_000_000 / 120);

#[derive(Clone)]
pub struct Step {
    pub group: Option<String>,
    pub name: String,
    pub total: u64,
    pub unit: &'static str,
    completed: Arc<AtomicU64>,
    requested: Arc<AtomicBool>,
    text: Arc<Mutex<Text>>,
}

#[derive(Clone, Default)]
pub struct Text {
    pub detail: String,
    pub finished: bool,
}

#[derive(Clone)]
pub struct Record {
    pub group: Option<String>,
    pub name: String,
    pub detail: String,
}

impl Step {
    pub fn set(&self, completed: u64) {
        self.completed.store(completed, Ordering::Relaxed);
    }

    pub fn completed(&self) -> u64 {
        self.completed.load(Ordering::Relaxed)
    }

    pub fn detail(&self, detail: impl Into<String>) {
        self.text.lock().expect("progress lock poisoned").detail = detail.into();
    }

    pub fn request(&self) {
        self.requested.store(true, Ordering::Relaxed);
    }

    #[inline]
    pub fn sample(&self) -> bool {
        self.requested.load(Ordering::Relaxed) && self.requested.swap(false, Ordering::Relaxed)
    }

    pub fn finish(&self, result: impl Into<String>) {
        self.set(self.total);
        *self.text.lock().expect("progress lock poisoned") = Text {
            detail: result.into(),
            finished: true,
        };
    }

    pub fn text(&self) -> Text {
        self.text.lock().expect("progress lock poisoned").clone()
    }
}

#[derive(Clone, Default)]
pub struct Progress {
    group: Option<String>,
    steps: Arc<Mutex<Vec<Step>>>,
    records: Arc<Mutex<Vec<Arc<Record>>>>,
    cancelled: Arc<AtomicBool>,
    wake: Arc<(Mutex<()>, Condvar)>,
}

impl Progress {
    pub fn group(&self, name: impl Into<String>) -> Self {
        Self {
            group: Some(name.into()),
            ..self.clone()
        }
    }

    pub fn start(&self, name: impl Into<String>, total: u64, unit: &'static str) -> Step {
        let step = Step {
            group: self.group.clone(),
            name: name.into(),
            total,
            unit,
            completed: Arc::default(),
            requested: Arc::new(AtomicBool::new(true)),
            text: Arc::default(),
        };
        self.steps
            .lock()
            .expect("progress lock poisoned")
            .push(step.clone());
        step
    }

    pub fn activity(&self, name: impl Into<String>) -> Step {
        self.start(name, 0, "")
    }

    pub fn record(&self, name: &str, item: &str) {
        let mut records = self.records.lock().expect("progress lock poisoned");
        if let Some(record) = records
            .last_mut()
            .filter(|record| record.group == self.group && record.name == name)
        {
            let record = Arc::make_mut(record);
            record.detail.push('、');
            record.detail.push_str(item);
        } else {
            records.push(Arc::new(Record {
                group: self.group.clone(),
                name: name.to_owned(),
                detail: item.to_owned(),
            }));
        }
    }

    pub fn records(&self) -> Vec<Arc<Record>> {
        self.records.lock().expect("progress lock poisoned").clone()
    }

    pub fn fail(&self, error: &str) {
        for step in self.steps() {
            if step.group == self.group {
                step.text.lock().expect("progress lock poisoned").finished = true;
            }
        }
        self.record("操作失败", error);
    }

    pub fn steps(&self) -> Vec<Step> {
        self.steps.lock().expect("progress lock poisoned").clone()
    }

    pub fn cancel(&self) {
        let _guard = self.wake.0.lock().expect("progress lock poisoned");
        self.cancelled.store(true, Ordering::Relaxed);
        self.wake.1.notify_all();
    }

    pub fn wait(&self, duration: Duration) -> Result<()> {
        let guard = self.wake.0.lock().expect("progress lock poisoned");
        drop(
            self.wake
                .1
                .wait_timeout_while(guard, duration, |_| !self.cancelled.load(Ordering::Relaxed))
                .expect("progress lock poisoned"),
        );
        self.check()
    }

    pub fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(Error::new(ErrorKind::Interrupted, "已取消").into());
        }
        Ok(())
    }

    pub fn notify(&self) {
        let _guard = self.wake.0.lock().expect("progress lock poisoned");
        self.wake.1.notify_all();
    }

    pub fn until(&self, mut ready: impl FnMut() -> Result<bool>) -> Result<()> {
        let mut guard = self.wake.0.lock().expect("progress lock poisoned");
        loop {
            self.check()?;
            if ready()? {
                return Ok(());
            }
            guard = self.wake.1.wait(guard).expect("progress lock poisoned");
        }
    }
}
