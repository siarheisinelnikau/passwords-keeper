use passwords_keeper::settings::Settings;
use std::{sync::mpsc, thread};
pub struct PreferencesWorker {
    sender: mpsc::Sender<Option<Settings>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl PreferencesWorker {
    pub fn start(on_error: impl Fn() + Send + 'static) -> Self {
        let (sender, receiver) = mpsc::channel::<Option<Settings>>();
        let thread = thread::Builder::new()
            .name("preferences-writer".into())
            .spawn(move || {
                while let Ok(Some(mut prefs)) = receiver.recv() {
                    let mut exit = false;
                    for queued in receiver.try_iter() {
                        if let Some(latest) = queued {
                            prefs = latest;
                        } else {
                            exit = true;
                            break;
                        }
                    }
                    if prefs.save(&Settings::path()).is_err() {
                        on_error();
                    }
                    if exit {
                        break;
                    }
                }
            })
            .expect("start preferences writer");
        Self {
            sender,
            thread: Some(thread),
        }
    }
    pub fn save(&self, prefs: Settings) {
        let _ = self.sender.send(Some(prefs));
    }
}
impl Drop for PreferencesWorker {
    fn drop(&mut self) {
        let _ = self.sender.send(None);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
