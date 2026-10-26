use std::{
    io::{Error, ErrorKind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::Result;

pub const FRAME: Duration = Duration::from_nanos(1_000_000_000 / 120);

#[derive(Default)]
struct State {
    steps: Mutex<Vec<Arc<Step>>>,
    cancelled: AtomicBool,
}

#[derive(Clone, Default)]
pub struct Progress {
    state: Arc<State>,
}

pub struct Step {
    pub name: String,
    pub total: u64,
    pub unit: String,
    completed: AtomicU64,
    text: Mutex<Text>,
}

#[derive(Clone, Default)]
pub struct Text {
    pub detail: String,
    pub finished: bool,
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

    pub fn finish(&self, detail: impl Into<String>) {
        self.set(self.total);
        *self.text.lock().expect("progress lock poisoned") = Text {
            detail: detail.into(),
            finished: true,
        };
    }

    pub fn text(&self) -> Text {
        self.text.lock().expect("progress lock poisoned").clone()
    }
}

impl Progress {
    pub fn start(&self, name: impl Into<String>, total: u64, unit: impl Into<String>) -> Arc<Step> {
        let step = Arc::new(Step {
            name: name.into(),
            total,
            unit: unit.into(),
            completed: AtomicU64::new(0),
            text: Mutex::new(Text::default()),
        });
        self.state
            .steps
            .lock()
            .expect("progress lock poisoned")
            .push(step.clone());
        step
    }

    pub fn activity(&self, name: impl Into<String>) -> Arc<Step> {
        self.start(name, 0, "")
    }

    pub fn steps(&self) -> Vec<Arc<Step>> {
        self.state
            .steps
            .lock()
            .expect("progress lock poisoned")
            .clone()
    }

    pub fn cancel(&self) {
        self.state.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn check(&self) -> Result<()> {
        if self.state.cancelled.load(Ordering::Relaxed) {
            return Err(Error::new(ErrorKind::Interrupted, "操作已取消").into());
        }
        Ok(())
    }
}
