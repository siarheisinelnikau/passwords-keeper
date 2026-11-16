//! Windows adapters are constructed only by the normal desktop entry point.
//! Unit tests use the Clipboard trait and injected session events instead.
use crate::{
    error::{Result, VaultError},
    i18n,
    security::Clipboard,
    settings::Language,
};
use std::{
    sync::{Arc, RwLock, mpsc},
    thread,
};

#[derive(Clone, Copy, Debug)]
pub enum SystemEvent {
    SessionLocked,
    Open,
    Lock,
    Quit,
}
#[cfg(windows)]
mod win {
    use super::*;
    use std::{
        mem::{size_of, zeroed},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::*,
        System::{DataExchange::*, LibraryLoader::GetModuleHandleW, Memory::*, RemoteDesktop::*},
        UI::{Shell::*, WindowsAndMessaging::*},
    };
    const TRAY_MESSAGE: u32 = WM_APP + 12;
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    struct State {
        send: Box<dyn Fn(SystemEvent) + Send>,
        language: Arc<RwLock<Language>>,
        icon: NOTIFYICONDATAW,
    }
    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        unsafe {
            if msg == WM_NCCREATE {
                let create = &*(lparam as *const CREATESTRUCTW);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize);
            }
            let state = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut State;
            if !state.is_null() {
                let state = &mut *state;
                match msg {
                    WM_WTSSESSION_CHANGE if wparam == WTS_SESSION_LOCK as usize => {
                        (state.send)(SystemEvent::SessionLocked);
                        return 0;
                    }
                    TRAY_MESSAGE => {
                        let event = lparam as u32 & 0xffff;
                        if event == WM_LBUTTONUP || event == NIN_SELECT {
                            (state.send)(SystemEvent::Open);
                        } else if event == WM_RBUTTONUP || event == WM_CONTEXTMENU {
                            let menu = CreatePopupMenu();
                            let language =
                                *state.language.read().unwrap_or_else(|e| e.into_inner());
                            for (id, label) in [(1, "open_app"), (2, "lock"), (3, "quit")] {
                                AppendMenuW(
                                    menu,
                                    MF_STRING,
                                    id,
                                    wide(i18n::text(language, label)).as_ptr(),
                                );
                            }
                            let mut point: POINT = zeroed();
                            GetCursorPos(&mut point);
                            SetForegroundWindow(hwnd);
                            let choice = TrackPopupMenu(
                                menu,
                                TPM_RETURNCMD | TPM_RIGHTBUTTON,
                                point.x,
                                point.y,
                                0,
                                hwnd,
                                ptr::null(),
                            ) as usize;
                            DestroyMenu(menu);
                            PostMessageW(hwnd, WM_NULL, 0, 0);
                            if let Some(action) = match choice {
                                1 => Some(SystemEvent::Open),
                                2 => Some(SystemEvent::Lock),
                                3 => Some(SystemEvent::Quit),
                                _ => None,
                            } {
                                (state.send)(action);
                            }
                        }
                        return 0;
                    }
                    WM_CLOSE => {
                        DestroyWindow(hwnd);
                        return 0;
                    }
                    WM_DESTROY => {
                        WTSUnRegisterSessionNotification(hwnd);
                        Shell_NotifyIconW(NIM_DELETE, &state.icon);
                        PostQuitMessage(0);
                        return 0;
                    }
                    _ => {}
                }
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
    }
    pub struct Monitor {
        pub hwnd: usize,
        thread: Option<thread::JoinHandle<()>>,
        language: Arc<RwLock<Language>>,
    }
    impl Monitor {
        pub fn start(
            language: Language,
            send: impl Fn(SystemEvent) + Send + 'static,
        ) -> std::io::Result<Self> {
            let language = Arc::new(RwLock::new(language));
            let shared = language.clone();
            let (tx, rx) = mpsc::sync_channel(1);
            let thread = thread::Builder::new()
                .name("windows-session-and-tray".into())
                .spawn(move || unsafe {
                    let instance = GetModuleHandleW(ptr::null());
                    let class = wide("PasswordsKeeperSessionWindow");
                    let wc = WNDCLASSW {
                        lpfnWndProc: Some(window_proc),
                        hInstance: instance,
                        lpszClassName: class.as_ptr(),
                        ..zeroed()
                    };
                    if RegisterClassW(&wc) == 0 {
                        let _ = tx.send(0);
                        return;
                    }
                    let mut state = Box::new(State {
                        send: Box::new(send),
                        language: shared,
                        icon: zeroed(),
                    });
                    let hwnd = CreateWindowExW(
                        0,
                        class.as_ptr(),
                        wide("Passwords Keeper").as_ptr(),
                        0,
                        0,
                        0,
                        0,
                        0,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        instance,
                        (&mut *state as *mut State).cast(),
                    );
                    if hwnd.is_null() {
                        let _ = tx.send(0);
                        return;
                    }
                    if WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) == 0 {
                        DestroyWindow(hwnd);
                        let _ = tx.send(0);
                        return;
                    }
                    let icon = LoadImageW(
                        instance,
                        std::ptr::without_provenance::<u16>(1),
                        IMAGE_ICON,
                        GetSystemMetrics(SM_CXSMICON).max(16),
                        GetSystemMetrics(SM_CYSMICON).max(16),
                        LR_DEFAULTCOLOR,
                    ) as HICON;
                    state.icon.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
                    state.icon.hWnd = hwnd;
                    state.icon.uID = 1;
                    state.icon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
                    state.icon.uCallbackMessage = TRAY_MESSAGE;
                    state.icon.hIcon = icon;
                    let tip = wide("Passwords Keeper");
                    state.icon.szTip[..tip.len()].copy_from_slice(&tip);
                    let _ = Shell_NotifyIconW(NIM_ADD, &state.icon);
                    let _ = tx.send(hwnd as usize);
                    let mut message: MSG = zeroed();
                    while GetMessageW(&mut message, ptr::null_mut(), 0, 0) > 0 {
                        TranslateMessage(&message);
                        DispatchMessageW(&message);
                    }
                    if !icon.is_null() {
                        DestroyIcon(icon);
                    }
                    UnregisterClassW(class.as_ptr(), instance);
                })?;
            let hwnd = rx.recv().unwrap_or(0);
            if hwnd == 0 {
                let _ = thread.join();
                return Err(std::io::Error::other(
                    "Windows session notification registration failed",
                ));
            }
            Ok(Self {
                hwnd,
                thread: Some(thread),
                language,
            })
        }
        pub fn set_language(&self, value: Language) {
            if let Ok(mut language) = self.language.write() {
                *language = value;
            }
        }
    }
    impl Drop for Monitor {
        fn drop(&mut self) {
            unsafe {
                PostMessageW(self.hwnd as HWND, WM_CLOSE, 0, 0);
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
    struct ClipboardOpen;
    impl Drop for ClipboardOpen {
        fn drop(&mut self) {
            unsafe {
                CloseClipboard();
            }
        }
    }
    fn open(hwnd: usize) -> Result<ClipboardOpen> {
        if unsafe { OpenClipboard(hwnd as HWND) } == 0 {
            Err(VaultError::Clipboard)
        } else {
            Ok(ClipboardOpen)
        }
    }
    unsafe fn set_bytes(format: u32, bytes: &[u8]) -> Result<()> {
        unsafe {
            let memory = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes.len());
            if memory.is_null() {
                return Err(VaultError::Clipboard);
            }
            let buffer = GlobalLock(memory);
            if buffer.is_null() {
                GlobalFree(memory);
                return Err(VaultError::Clipboard);
            }
            ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.cast::<u8>(), bytes.len());
            GlobalUnlock(memory);
            if SetClipboardData(format, memory).is_null() {
                GlobalFree(memory);
                return Err(VaultError::Clipboard);
            }
            Ok(())
        }
    }
    pub struct WindowsClipboard {
        hwnd: usize,
        format: u32,
        nonce: [u8; 16],
    }
    impl WindowsClipboard {
        pub fn new(hwnd: usize) -> Self {
            Self {
                hwnd,
                format: 0,
                nonce: [0; 16],
            }
        }
    }
    impl Clipboard for WindowsClipboard {
        fn read_text(&mut self) -> Result<zeroize::Zeroizing<String>> {
            let _guard = open(self.hwnd)?;
            unsafe {
                let memory = GetClipboardData(13);
                if memory.is_null() {
                    return Err(VaultError::Clipboard);
                }
                let bytes = GlobalSize(memory);
                if bytes == 0 || bytes > 512 * 1024 || !bytes.is_multiple_of(2) {
                    return Err(VaultError::Clipboard);
                }
                let data = GlobalLock(memory);
                if data.is_null() {
                    return Err(VaultError::Clipboard);
                }
                let units = std::slice::from_raw_parts(data.cast::<u16>(), bytes / 2);
                let end = units.iter().position(|v| *v == 0).unwrap_or(units.len());
                let text = String::from_utf16(&units[..end]).map_err(|_| VaultError::Clipboard);
                GlobalUnlock(memory);
                Ok(zeroize::Zeroizing::new(text?))
            }
        }
        fn write_secret(&mut self, text: &str) -> Result<u64> {
            if self.format == 0 {
                self.format = unsafe {
                    RegisterClipboardFormatW(wide("PasswordsKeeperOwnership-v1").as_ptr())
                };
            }
            if self.format == 0 {
                return Err(VaultError::Clipboard);
            }
            getrandom::fill(&mut self.nonce).map_err(|_| VaultError::Random)?;
            let data = zeroize::Zeroizing::new(wide(text));
            let bytes = bytemuck::cast_slice(&data);
            {
                let _guard = open(self.hwnd)?;
                unsafe {
                    if EmptyClipboard() == 0 {
                        return Err(VaultError::Clipboard);
                    }
                    set_bytes(self.format, &self.nonce)?;
                    for name in ["CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"] {
                        let format = RegisterClipboardFormatW(wide(name).as_ptr());
                        if format != 0 {
                            set_bytes(format, &0u32.to_le_bytes())?;
                        }
                    }
                    let excluded = RegisterClipboardFormatW(
                        wide("ExcludeClipboardContentFromMonitorProcessing").as_ptr(),
                    );
                    if excluded != 0 {
                        set_bytes(excluded, &0u32.to_le_bytes())?;
                    }
                    set_bytes(13, bytes)?;
                }
            }
            Ok(unsafe { GetClipboardSequenceNumber() } as u64)
        }
        fn clear_if_owned(&mut self, token: u64) -> Result<bool> {
            let _guard = open(self.hwnd)?;
            unsafe {
                if GetClipboardOwner() != self.hwnd as HWND
                    || GetClipboardSequenceNumber() as u64 != token
                {
                    return Ok(false);
                }
                let marker = GetClipboardData(self.format);
                if marker.is_null() || GlobalSize(marker) != 16 {
                    return Ok(false);
                }
                let pointer = GlobalLock(marker);
                if pointer.is_null() {
                    return Err(VaultError::Clipboard);
                }
                let matches = std::slice::from_raw_parts(pointer.cast::<u8>(), 16) == self.nonce;
                GlobalUnlock(marker);
                if !matches {
                    return Ok(false);
                }
                if EmptyClipboard() == 0 {
                    return Err(VaultError::Clipboard);
                }
                Ok(true)
            }
        }
    }
    pub fn error_dialog(message: &str) {
        unsafe {
            MessageBoxW(
                ptr::null_mut(),
                wide(message).as_ptr(),
                wide("Passwords Keeper").as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
}
#[cfg(windows)]
pub use win::*;
