use std::error::Error;
use std::process::Command;

pub type DryError = Box<dyn Error + Send + Sync + 'static>;

pub struct TracedChildTree {}

#[derive(Debug, Copy, Clone)]
pub enum ProcessEvent {
    SyscallEnter {
        syscall_number: u64,
        args: [u64; 6],
    },
    SyscallExit {
        return_val: i64,
        is_error: bool,
    },
    Event {
        event_pid: u32,
        ty: (),
    },
    SignalDelivery {
        signal: i32,
    },
    ExitNormally(i32),
    ExitSignal(i32),
}

pub struct ProcessEventActor<A> {
    item: Option<A>,
    action: ProcessEventAction,
}

pub enum ProcessEventAction {
    Resume,
    Detach,
    Signal(i32),
}

impl<A> ProcessEventActor<A> {
    pub fn resume_with(item: A) -> Self {
        ProcessEventActor {
            item: Some(item),
            action: ProcessEventAction::Resume,
        }
    }
}

pub struct TracedChildTreeIter<F> {
    tree: TracedChildTree,
    action: F,
}

pub trait TracingCommand {
    fn spawn_with_tracing(&self) -> Result<TracedChildTree, DryError>;
}

impl TracingCommand for Command {
    fn spawn_with_tracing(&self) -> Result<TracedChildTree, DryError> {
        Ok(TracedChildTree {})
    }
}

pub trait TracedChildTreeExt {
    fn next_event(&self) -> Result<ProcessEvent, DryError>;

    fn detach(&self) -> Result<(), DryError>;

    fn resume(&self) -> Result<(), DryError>;

    fn signal(&self, signumber: i32) -> Result<(), DryError>;
}

impl TracedChildTree {
    pub fn on_process_event<F, R>(self, action: F) -> TracedChildTreeIter<F> where F: for<'r> FnMut(&'r ProcessEvent) -> ProcessEventActor<R> {
        TracedChildTreeIter {
            tree: self,
            action,
        }
    }
}

impl TracedChildTreeExt for TracedChildTree {
    fn next_event(&self) -> Result<ProcessEvent, DryError> {
        unimplemented!()
    }

    fn detach(&self) -> Result<(), DryError> {
        unimplemented!()
    }

    fn resume(&self) -> Result<(), DryError> {
        unimplemented!()
    }

    fn signal(&self, signumber: i32) -> Result<(), DryError> {
        unimplemented!()
    }
}

impl<F, R> Iterator for TracedChildTreeIter<F> where F: for<'r> FnMut(&'r ProcessEvent) -> ProcessEventActor<R> {
    type Item = Result<R, DryError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.tree.next_event() {
                Ok(ev) => {
                    // TODO: register panic handler to resume/detach child in case of panic in user code
                    let result = (self.action)(&ev);
                    use ProcessEventAction::*;
                    let action_result = match result.action {
                        Resume => self.tree.resume(),
                        Detach => self.tree.detach(),
                        Signal(signumber) => self.tree.signal(signumber),
                    };

                    match action_result {
                        Ok(_) => (),
                        Err(e) => return Some(Err(e)),
                    }
                    match result.item {
                        Some(v) => return Some(Ok(v)),
                        None => (),
                    }
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }
}
