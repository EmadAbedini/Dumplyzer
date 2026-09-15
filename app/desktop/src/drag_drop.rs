//! Windows file-drop handler.
//!
//! OLE drop targeting is per-HWND. Empirical HWND tree:
//!
//! ```text
//! Tauri Window              UI thread     ← title bar / non-client (RegisterDragDrop works)
//!   WRY_WEBVIEW             UI thread
//!     Chrome_WidgetWin_0    UI thread
//!       Chrome_WidgetWin_1  Chromium thread  ← client area hit-test
//!         Chrome_RenderWidgetHostHWND
//!         Intermediate D3D Window
//! ```
//!
//! Explorer uses `WindowFromPoint` (deepest child). Content drops therefore hit
//! `Chrome_WidgetWin_1` / `Chrome_RenderWidgetHostHWND`, which are **not** on the
//! Tauri UI thread. `RegisterDragDrop` must run on the creating thread;
//! `SetWindowsHookEx` on those threads returns ACCESS_DENIED.
//!
//! Content-area drops are captured by a same-thread layered child overlay that
//! covers the Tauri **client** rect and is shown only while an Explorer drag
//! that started outside the window is over that client area. Title-bar drops
//! still use `IDropTarget` on the top-level HWND.
//!
//! Paths: `CF_HDROP` → `dumplyzer://file-drop` → `importFromPath`.

use serde::Serialize;
use std::path::PathBuf;
use tauri::{AppHandle, Emitter, Manager, WebviewWindow};

const EVENT: &str = "dumplyzer://file-drop";

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum FileDropNotice {
    Enter { paths: Vec<String> },
    Over,
    Drop { paths: Vec<String> },
    Leave,
}

pub fn attach_after_show(app: &AppHandle, window: &WebviewWindow) {
    #[cfg(windows)]
    windows_impl::schedule(app, window);
    #[cfg(not(windows))]
    let _ = (app, window);
}

/// Remove the global mouse hook before the UI thread blocks on shutdown.
/// Leaving `WH_MOUSE_LL` installed while the process dies stalls the system cursor.
pub fn teardown() {
    #[cfg(windows)]
    windows_impl::teardown();
}

pub fn emit_tauri_drag(app: &AppHandle, event: &tauri::DragDropEvent) {
    let notice = match event {
        tauri::DragDropEvent::Enter { paths, .. } => FileDropNotice::Enter {
            paths: paths_to_strings(paths),
        },
        tauri::DragDropEvent::Over { .. } => FileDropNotice::Over,
        tauri::DragDropEvent::Drop { paths, .. } => FileDropNotice::Drop {
            paths: paths_to_strings(paths),
        },
        tauri::DragDropEvent::Leave => FileDropNotice::Leave,
        _ => return,
    };
    emit_notice(app, &notice);
}

fn emit_notice(app: &AppHandle, notice: &FileDropNotice) {
    match notice {
        FileDropNotice::Enter { paths } => {
            eprintln!("dumplyzer: file-drop enter count={}", paths.len());
        }
        FileDropNotice::Drop { paths } => {
            eprintln!(
                "dumplyzer: file-drop drop count={} first={}",
                paths.len(),
                paths.first().map(String::as_str).unwrap_or("-")
            );
        }
        FileDropNotice::Leave => eprintln!("dumplyzer: file-drop leave"),
        FileDropNotice::Over => {}
    }
    let _ = app.emit(EVENT, notice);
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.emit(EVENT, notice);
    }
}

fn paths_to_strings(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(windows)]
mod windows_impl {
    use super::{emit_notice, paths_to_strings, FileDropNotice};
    use std::cell::{Cell, RefCell};
    use std::collections::HashSet;
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
    use std::sync::{Arc, LazyLock, Mutex, OnceLock};
    use std::time::Duration;
    use tauri::{AppHandle, Manager, WebviewWindow};

    use windows::{
        core::BOOL,
        Win32::{
            Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, POINT, POINTL, RECT, WPARAM},
            Graphics::Gdi::{HBRUSH, MapWindowPoints, PtInRect, ScreenToClient},
            System::{
                Com::{IDataObject, DVASPECT_CONTENT, FORMATETC, TYMED_HGLOBAL},
                LibraryLoader::GetModuleHandleW,
                Ole::{
                    IDropTarget, IDropTarget_Impl, OleInitialize, RegisterDragDrop, RevokeDragDrop,
                    CF_HDROP, DROPEFFECT, DROPEFFECT_COPY, DROPEFFECT_NONE,
                },
                SystemServices::MODIFIERKEYS_FLAGS,
                Threading::{GetCurrentProcessId, GetCurrentThreadId},
            },
            UI::{
                Accessibility::{HWINEVENTHOOK, SetWinEventHook, UnhookWinEvent},
                Shell::{DragFinish, DragQueryFileW, HDROP},
                WindowsAndMessaging::{
                    CallNextHookEx, CreateWindowExW, DefWindowProcW, EnumChildWindows,
                    GetClassNameW, GetClientRect, GetParent, GetWindow, GetWindowRect,
                    GetWindowThreadProcessId, IsWindow, IsWindowVisible, PostMessageW,
                    RegisterClassW, SetLayeredWindowAttributes, SetWindowPos, SetWindowsHookExW,
                    ShowWindow, UnhookWindowsHookEx, WindowFromPoint, CS_HREDRAW, CS_VREDRAW,
                    DestroyWindow, EVENT_OBJECT_CREATE, EVENT_OBJECT_SHOW, GW_CHILD, GW_HWNDNEXT,
                    HCURSOR, HHOOK, HICON, HWND_TOP, HWND_TOPMOST, LWA_ALPHA, MSLLHOOKSTRUCT,
                    SWP_NOACTIVATE, SW_HIDE, SW_SHOWNOACTIVATE, WH_MOUSE_LL, WINEVENT_OUTOFCONTEXT,
                    WM_APP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WNDCLASSW, WS_CHILD,
                    WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
                },
            },
        },
    };
    use windows_core::{implement, w, Interface};
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Controller4;

    thread_local! {
        static TARGETS: RefCell<Vec<IDropTarget>> = RefCell::new(Vec::new());
    }

    static REGISTERED: LazyLock<Mutex<HashSet<usize>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
    static LISTENER: Mutex<Option<Arc<dyn Fn(Notice) + Send + Sync>>> = Mutex::new(None);
    static INJECT_CTX: Mutex<Option<(AppHandle, String)>> = Mutex::new(None);
    static TREE_DUMPED: Mutex<String> = Mutex::new(String::new());
    static WINEVENT_HOOK: AtomicIsize = AtomicIsize::new(0);
    static OVERLAY: AtomicUsize = AtomicUsize::new(0);
    static OVERLAY_PARENT: AtomicUsize = AtomicUsize::new(0);
    static MOUSE_HOOK: AtomicIsize = AtomicIsize::new(0);
    static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);
    static LB_DOWN: AtomicBool = AtomicBool::new(false);
    static DRAG_FROM_OUTSIDE: AtomicBool = AtomicBool::new(false);
    static OVERLAY_SHOWN: AtomicBool = AtomicBool::new(false);
    static OVERLAY_IS_POPUP: AtomicBool = AtomicBool::new(false);
    static LOGGED_OTHER: LazyLock<Mutex<HashSet<usize>>> =
        LazyLock::new(|| Mutex::new(HashSet::new()));

    const WM_SHOW_DROP_OVERLAY: u32 = WM_APP + 41;
    const WM_HIDE_DROP_OVERLAY: u32 = WM_APP + 42;

    #[derive(Clone)]
    enum Notice {
        Enter(Vec<PathBuf>),
        Over,
        Drop(Vec<PathBuf>),
        Leave,
    }

    pub fn schedule(app: &AppHandle, window: &WebviewWindow) {
        if SHUTTING_DOWN.load(Ordering::SeqCst) {
            return;
        }
        if let Ok(mut ctx) = INJECT_CTX.lock() {
            *ctx = Some((app.clone(), window.label().to_string()));
        }
        install_window_create_hook();
        inject(app, window);
        for delay in [100_u64, 250, 800, 2000, 4000, 8000, 15000] {
            let app = app.clone();
            let label = window.label().to_string();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(delay));
                if SHUTTING_DOWN.load(Ordering::SeqCst) {
                    return;
                }
                let bounced = app.clone();
                let _ = bounced.run_on_main_thread(move || {
                    if SHUTTING_DOWN.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Some(win) = app.get_webview_window(&label) {
                        inject(&app, &win);
                    }
                });
            });
        }
    }

    pub fn inject(app: &AppHandle, window: &WebviewWindow) {
        if SHUTTING_DOWN.load(Ordering::SeqCst) {
            return;
        }
        let _ = unsafe { OleInitialize(None) };
        let listener = make_listener(app);
        if let Ok(mut slot) = LISTENER.lock() {
            *slot = Some(listener.clone());
        }

        if let Ok(hwnd) = window.hwnd() {
            let hwnd = HWND(hwnd.0 as _);
            dump_tree_if_changed(hwnd);
            register_tree(hwnd, listener.clone());
            ensure_client_drop_overlay(hwnd, listener.clone());
        }

        let app = app.clone();
        let _ = window.with_webview(move |webview| {
            let controller = webview.controller();
            unsafe {
                // HTML5 drops have no filesystem paths. Keep OLE on our IDropTarget.
                let _ = controller
                    .cast::<ICoreWebView2Controller4>()
                    .and_then(|c| c.SetAllowExternalDrop(false));
                let mut hwnd = HWND::default();
                if controller.ParentWindow(&mut hwnd).is_ok() && !hwnd.is_invalid() {
                    dump_tree_if_changed(hwnd);
                    register_tree(hwnd, make_listener(&app));
                }
            }
        });
    }

    pub fn teardown() {
        SHUTTING_DOWN.store(true, Ordering::SeqCst);
        let mouse = MOUSE_HOOK.swap(0, Ordering::SeqCst);
        if mouse != 0 {
            let _ = unsafe { UnhookWindowsHookEx(HHOOK(mouse as *mut c_void)) };
            eprintln!("dumplyzer: WH_MOUSE_LL removed");
        }
        let winevent = WINEVENT_HOOK.swap(0, Ordering::SeqCst);
        if winevent != 0 {
            let _ = unsafe { UnhookWinEvent(HWINEVENTHOOK(winevent as *mut c_void)) };
        }
        LB_DOWN.store(false, Ordering::Relaxed);
        DRAG_FROM_OUTSIDE.store(false, Ordering::Relaxed);
        OVERLAY_SHOWN.store(false, Ordering::Relaxed);
        OVERLAY_PARENT.store(0, Ordering::SeqCst);
        if let Ok(mut ctx) = INJECT_CTX.lock() {
            *ctx = None;
        }
        if let Ok(mut slot) = LISTENER.lock() {
            *slot = None;
        }
        let overlay = hwnd_from_key(OVERLAY.swap(0, Ordering::SeqCst));
        if !overlay.is_invalid() {
            let _ = unsafe { RevokeDragDrop(overlay) };
            let _ = unsafe { DestroyWindow(overlay) };
        }
        TARGETS.with(|targets| targets.borrow_mut().clear());
    }

    fn make_listener(app: &AppHandle) -> Arc<dyn Fn(Notice) + Send + Sync> {
        let app = app.clone();
        Arc::new(move |notice: Notice| {
            let payload = match notice {
                Notice::Enter(paths) => FileDropNotice::Enter {
                    paths: paths_to_strings(&paths),
                },
                Notice::Over => FileDropNotice::Over,
                Notice::Drop(paths) => FileDropNotice::Drop {
                    paths: paths_to_strings(&paths),
                },
                Notice::Leave => FileDropNotice::Leave,
            };
            emit_notice(&app, &payload);
        })
    }

    fn hwnd_key(hwnd: HWND) -> usize {
        hwnd.0 as usize
    }

    fn hwnd_from_key(key: usize) -> HWND {
        HWND(key as *mut c_void)
    }

    fn class_name(hwnd: HWND) -> String {
        let mut buf = [0u16; 256];
        let n = unsafe { GetClassNameW(hwnd, &mut buf) } as usize;
        String::from_utf16_lossy(&buf[..n.min(buf.len())])
    }

    fn describe_hwnd(hwnd: HWND) -> String {
        let class = class_name(hwnd);
        let mut pid = 0u32;
        let thread = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        let ui = unsafe { GetCurrentThreadId() };
        let our_pid = unsafe { GetCurrentProcessId() };
        let vis = unsafe { IsWindowVisible(hwnd).as_bool() };
        let mut rc = windows::Win32::Foundation::RECT::default();
        let _ = unsafe { GetWindowRect(hwnd, &mut rc) };
        let registered = REGISTERED
            .lock()
            .map(|s| s.contains(&hwnd_key(hwnd)))
            .unwrap_or(false);
        format!(
            "{:p} class={class} pid={pid} thread={thread} ui={ui} vis={vis} rect=({left},{top}; {right},{bottom}) {state}",
            hwnd.0,
            left = rc.left,
            top = rc.top,
            right = rc.right,
            bottom = rc.bottom,
            state = if registered {
                "[REGISTERED]"
            } else if thread != ui {
                if pid != our_pid {
                    "[OTHER-PROCESS]"
                } else {
                    "[OTHER-THREAD]"
                }
            } else {
                "[unregistered]"
            }
        )
    }

    fn dump_tree_if_changed(root: HWND) {
        let mut lines = Vec::new();
        collect_tree(root, 0, &mut lines);
        let signature = lines.join("\n");
        let mut prev = match TREE_DUMPED.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if *prev == signature {
            return;
        }
        *prev = signature.clone();
        eprintln!("dumplyzer: HWND tree (OLE drop targets):\n{signature}");
    }

    fn collect_tree(hwnd: HWND, indent: usize, lines: &mut Vec<String>) {
        if hwnd.is_invalid() || !unsafe { IsWindow(Some(hwnd)).as_bool() } {
            return;
        }
        lines.push(format!(
            "{:indent$}{}",
            "",
            describe_hwnd(hwnd),
            indent = indent
        ));
        let mut child = unsafe { GetWindow(hwnd, GW_CHILD) }.unwrap_or_default();
        while !child.is_invalid() {
            collect_tree(child, indent + 2, lines);
            child = unsafe { GetWindow(child, GW_HWNDNEXT) }.unwrap_or_default();
        }
    }

    fn register_tree(hwnd: HWND, listener: Arc<dyn Fn(Notice) + Send + Sync>) {
        if hwnd.is_invalid() {
            return;
        }
        let mut registered = Vec::new();
        visit_hwnd(hwnd, listener.clone(), &mut registered);
        enum_children(hwnd, listener, &mut registered);
        if !registered.is_empty() {
            eprintln!(
                "dumplyzer: registered file-drop on {} additional HWND(s)",
                registered.len()
            );
        }
        TARGETS.with(|targets| targets.borrow_mut().extend(registered));
    }

    fn visit_hwnd(
        hwnd: HWND,
        listener: Arc<dyn Fn(Notice) + Send + Sync>,
        out: &mut Vec<IDropTarget>,
    ) {
        if hwnd.is_invalid() || !unsafe { IsWindow(Some(hwnd)).as_bool() } {
            return;
        }
        let key = hwnd_key(hwnd);
        if REGISTERED.lock().map(|s| s.contains(&key)).unwrap_or(false) {
            return;
        }
        let hwnd_thread = unsafe { GetWindowThreadProcessId(hwnd, None) };
        let ui_thread = unsafe { GetCurrentThreadId() };
        if hwnd_thread == ui_thread {
            register_hwnd_here(hwnd, listener, out);
            return;
        }
        if LOGGED_OTHER.lock().ok().map(|mut s| s.insert(key)).unwrap_or(false) {
            eprintln!(
                "dumplyzer: content HWND is not on the UI thread (OLE will not hit parent): {}",
                describe_hwnd(hwnd)
            );
        }
    }

    fn enum_children(
        parent: HWND,
        listener: Arc<dyn Fn(Notice) + Send + Sync>,
        out: &mut Vec<IDropTarget>,
    ) {
        let mut callback = |child: HWND| {
            visit_hwnd(child, listener.clone(), out);
            true
        };
        let mut trait_obj: &mut dyn FnMut(HWND) -> bool = &mut callback;
        let closure_ptr: *mut c_void = unsafe { std::mem::transmute(&mut trait_obj) };
        let lparam = LPARAM(closure_ptr as isize);
        unsafe extern "system" fn enumerate_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
            let closure = &mut *(lparam.0 as *mut c_void as *mut &mut dyn FnMut(HWND) -> bool);
            closure(hwnd).into()
        }
        let _ = unsafe { EnumChildWindows(Some(parent), Some(enumerate_callback), lparam) };
    }

    fn register_hwnd_here(
        hwnd: HWND,
        listener: Arc<dyn Fn(Notice) + Send + Sync>,
        out: &mut Vec<IDropTarget>,
    ) {
        let target: IDropTarget = DragDropTarget::new(hwnd, listener).into();
        let _ = unsafe { RevokeDragDrop(hwnd) };
        match unsafe { RegisterDragDrop(hwnd, &target) } {
            Ok(()) => {
                REGISTERED.lock().ok().map(|mut s| s.insert(hwnd_key(hwnd)));
                eprintln!(
                    "dumplyzer: RegisterDragDrop ok {}",
                    describe_hwnd(hwnd)
                );
                out.push(target);
            }
            Err(err) => {
                eprintln!(
                    "dumplyzer: RegisterDragDrop FAILED {:#?} {}",
                    err.code(),
                    describe_hwnd(hwnd)
                );
            }
        }
    }

    fn ensure_client_drop_overlay(
        parent: HWND,
        listener: Arc<dyn Fn(Notice) + Send + Sync>,
    ) {
        if parent.is_invalid() {
            return;
        }
        OVERLAY_PARENT.store(hwnd_key(parent), Ordering::SeqCst);
        let existing = hwnd_from_key(OVERLAY.load(Ordering::SeqCst));
        if !existing.is_invalid() && unsafe { IsWindow(Some(existing)).as_bool() } {
            layout_overlay(parent, existing);
            install_mouse_hook();
            return;
        }

        register_overlay_class();
        let instance = match unsafe { GetModuleHandleW(windows_core::PCWSTR::null()) } {
            Ok(h) => HINSTANCE(h.0),
            Err(err) => {
                eprintln!("dumplyzer: GetModuleHandleW failed {:#?}", err.code());
                return;
            }
        };
        let mut rc = RECT::default();
        let _ = unsafe { GetClientRect(parent, &mut rc) };
        let child = unsafe {
            CreateWindowExW(
                WS_EX_LAYERED | WS_EX_NOACTIVATE,
                w!("DumplyzerDropOverlay"),
                w!(""),
                WS_CHILD,
                0,
                0,
                rc.right.max(1),
                rc.bottom.max(1),
                Some(parent),
                None,
                Some(instance),
                None,
            )
        };
        let (hwnd, popup) = match child {
            Ok(h) => (h, false),
            Err(err) => {
                eprintln!(
                    "dumplyzer: child drop overlay failed {:#?}; trying owned popup",
                    err.code()
                );
                match unsafe {
                    CreateWindowExW(
                        WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
                        w!("DumplyzerDropOverlay"),
                        w!(""),
                        WS_POPUP,
                        0,
                        0,
                        rc.right.max(1),
                        rc.bottom.max(1),
                        Some(parent),
                        None,
                        Some(instance),
                        None,
                    )
                } {
                    Ok(h) => (h, true),
                    Err(err2) => {
                        eprintln!(
                            "dumplyzer: create drop overlay FAILED {:#?}",
                            err2.code()
                        );
                        return;
                    }
                }
            }
        };
        OVERLAY_IS_POPUP.store(popup, Ordering::SeqCst);
        let _ = unsafe {
            SetLayeredWindowAttributes(hwnd, COLORREF(0), 1, LWA_ALPHA)
        };
        let wrapped = {
            let inner = listener.clone();
            Arc::new(move |notice: Notice| {
                if matches!(notice, Notice::Drop(_) | Notice::Leave) {
                    request_overlay_hidden();
                }
                inner(notice);
            }) as Arc<dyn Fn(Notice) + Send + Sync>
        };
        let mut registered = Vec::new();
        register_hwnd_here(hwnd, wrapped, &mut registered);
        TARGETS.with(|targets| targets.borrow_mut().extend(registered));
        OVERLAY.store(hwnd_key(hwnd), Ordering::SeqCst);
        eprintln!(
            "dumplyzer: client drop overlay ready {}",
            describe_hwnd(hwnd)
        );
        install_mouse_hook();
    }

    fn register_overlay_class() {
        static DONE: OnceLock<u16> = OnceLock::new();
        if DONE.get().is_some() {
            return;
        }
        let instance = match unsafe { GetModuleHandleW(windows_core::PCWSTR::null()) } {
            Ok(h) => HINSTANCE(h.0),
            Err(_) => return,
        };
        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(overlay_wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: HICON::default(),
            hCursor: HCURSOR::default(),
            hbrBackground: HBRUSH::default(),
            lpszMenuName: windows_core::PCWSTR::null(),
            lpszClassName: w!("DumplyzerDropOverlay"),
        };
        let atom = unsafe { RegisterClassW(&wc) };
        if atom == 0 {
            eprintln!("dumplyzer: RegisterClassW overlay failed");
            return;
        }
        let _ = DONE.set(atom);
        eprintln!("dumplyzer: registered overlay window class");
    }

    unsafe extern "system" fn overlay_wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_SHOW_DROP_OVERLAY => {
                show_overlay_now();
                LRESULT(0)
            }
            WM_HIDE_DROP_OVERLAY => {
                hide_overlay_now();
                LRESULT(0)
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    fn layout_overlay(parent: HWND, overlay: HWND) {
        let mut rc = RECT::default();
        let _ = unsafe { GetClientRect(parent, &mut rc) };
        let (x, y, cx, cy, after) = if OVERLAY_IS_POPUP.load(Ordering::SeqCst) {
            let mut pts = [
                POINT {
                    x: rc.left,
                    y: rc.top,
                },
                POINT {
                    x: rc.right,
                    y: rc.bottom,
                },
            ];
            unsafe { MapWindowPoints(Some(parent), None, &mut pts) };
            (
                pts[0].x,
                pts[0].y,
                (pts[1].x - pts[0].x).max(1),
                (pts[1].y - pts[0].y).max(1),
                HWND_TOPMOST,
            )
        } else {
            (0, 0, rc.right.max(1), rc.bottom.max(1), HWND_TOP)
        };
        let _ = unsafe {
            SetWindowPos(
                overlay,
                Some(after),
                x,
                y,
                cx,
                cy,
                SWP_NOACTIVATE,
            )
        };
    }

    fn show_overlay_now() {
        if SHUTTING_DOWN.load(Ordering::SeqCst) {
            return;
        }
        let parent = hwnd_from_key(OVERLAY_PARENT.load(Ordering::SeqCst));
        let overlay = hwnd_from_key(OVERLAY.load(Ordering::SeqCst));
        if overlay.is_invalid() || parent.is_invalid() {
            return;
        }
        layout_overlay(parent, overlay);
        let _ = unsafe { ShowWindow(overlay, SW_SHOWNOACTIVATE) };
        OVERLAY_SHOWN.store(true, Ordering::SeqCst);
        eprintln!("dumplyzer: client drop overlay SHOWN");
    }

    fn hide_overlay_now() {
        let overlay = hwnd_from_key(OVERLAY.load(Ordering::SeqCst));
        if overlay.is_invalid() {
            return;
        }
        let _ = unsafe { ShowWindow(overlay, SW_HIDE) };
        OVERLAY_SHOWN.store(false, Ordering::SeqCst);
    }

    fn request_overlay_shown() {
        if SHUTTING_DOWN.load(Ordering::Relaxed) || OVERLAY_SHOWN.load(Ordering::SeqCst) {
            return;
        }
        let overlay = hwnd_from_key(OVERLAY.load(Ordering::SeqCst));
        if overlay.is_invalid() {
            return;
        }
        let _ = unsafe { PostMessageW(Some(overlay), WM_SHOW_DROP_OVERLAY, WPARAM(0), LPARAM(0)) };
    }

    fn request_overlay_hidden() {
        if SHUTTING_DOWN.load(Ordering::Relaxed) || !OVERLAY_SHOWN.load(Ordering::SeqCst) {
            return;
        }
        let overlay = hwnd_from_key(OVERLAY.load(Ordering::SeqCst));
        if overlay.is_invalid() {
            return;
        }
        let _ = unsafe { PostMessageW(Some(overlay), WM_HIDE_DROP_OVERLAY, WPARAM(0), LPARAM(0)) };
    }

    fn point_in_our_window(root: HWND, pt: POINT) -> bool {
        let mut hwnd = unsafe { WindowFromPoint(pt) };
        while !hwnd.is_invalid() {
            if hwnd_key(hwnd) == hwnd_key(root) {
                return true;
            }
            hwnd = unsafe { GetParent(hwnd) }.unwrap_or_default();
        }
        false
    }

    fn point_in_client(root: HWND, pt: POINT) -> bool {
        if !point_in_our_window(root, pt) {
            return false;
        }
        let mut rc = RECT::default();
        if unsafe { GetClientRect(root, &mut rc) }.is_err() {
            return false;
        }
        let mut pts = [
            POINT {
                x: rc.left,
                y: rc.top,
            },
            POINT {
                x: rc.right,
                y: rc.bottom,
            },
        ];
        unsafe { MapWindowPoints(Some(root), None, &mut pts) };
        let screen = RECT {
            left: pts[0].x,
            top: pts[0].y,
            right: pts[1].x,
            bottom: pts[1].y,
        };
        unsafe { PtInRect(&screen, pt) }.as_bool()
    }

    fn install_mouse_hook() {
        if SHUTTING_DOWN.load(Ordering::SeqCst) || MOUSE_HOOK.load(Ordering::SeqCst) != 0 {
            return;
        }
        match unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_ll_hook), None, 0) } {
            Ok(hook) => {
                let id = hook.0 as isize;
                if MOUSE_HOOK
                    .compare_exchange(0, id, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
                {
                    let _ = unsafe { UnhookWindowsHookEx(hook) };
                    return;
                }
                eprintln!("dumplyzer: WH_MOUSE_LL installed for client-area file drops");
            }
            Err(err) => {
                eprintln!(
                    "dumplyzer: WH_MOUSE_LL FAILED {:#?} — content drops will not work",
                    err.code()
                );
            }
        }
    }

    unsafe extern "system" fn mouse_ll_hook(
        code: i32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if SHUTTING_DOWN.load(Ordering::Relaxed) {
            return unsafe { CallNextHookEx(None, code, wparam, lparam) };
        }
        if code >= 0 && lparam.0 != 0 {
            let info = &*(lparam.0 as *const MSLLHOOKSTRUCT);
            let parent = hwnd_from_key(OVERLAY_PARENT.load(Ordering::Relaxed));
            if !parent.is_invalid() {
                match wparam.0 as u32 {
                    WM_LBUTTONDOWN => {
                        let outside = !point_in_our_window(parent, info.pt);
                        LB_DOWN.store(true, Ordering::Relaxed);
                        DRAG_FROM_OUTSIDE.store(outside, Ordering::Relaxed);
                    }
                    WM_LBUTTONUP => {
                        LB_DOWN.store(false, Ordering::Relaxed);
                        DRAG_FROM_OUTSIDE.store(false, Ordering::Relaxed);
                        request_overlay_hidden();
                    }
                    WM_MOUSEMOVE => {
                        let dragging = LB_DOWN.load(Ordering::Relaxed)
                            && DRAG_FROM_OUTSIDE.load(Ordering::Relaxed);
                        let overlay_shown = OVERLAY_SHOWN.load(Ordering::Relaxed);
                        if dragging && point_in_client(parent, info.pt) {
                            request_overlay_shown();
                        } else if overlay_shown && !point_in_client(parent, info.pt) {
                            request_overlay_hidden();
                        }
                    }
                    _ => {}
                }
            }
        }
        unsafe { CallNextHookEx(None, code, wparam, lparam) }
    }

    fn install_window_create_hook() {
        if SHUTTING_DOWN.load(Ordering::SeqCst) || WINEVENT_HOOK.load(Ordering::SeqCst) != 0 {
            return;
        }
        let hook = unsafe {
            SetWinEventHook(
                EVENT_OBJECT_CREATE,
                EVENT_OBJECT_SHOW,
                None,
                Some(win_event_proc),
                GetCurrentProcessId(),
                0,
                WINEVENT_OUTOFCONTEXT,
            )
        };
        if hook.0.is_null() {
            eprintln!("dumplyzer: SetWinEventHook failed");
            return;
        }
        let id = hook.0 as isize;
        if WINEVENT_HOOK
            .compare_exchange(0, id, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            let _ = unsafe { UnhookWinEvent(hook) };
            return;
        }
        eprintln!("dumplyzer: watching HWND create/show for WebView2 children");
    }

    unsafe extern "system" fn win_event_proc(
        _hook: HWINEVENTHOOK,
        _event: u32,
        hwnd: HWND,
        _id_object: i32,
        _id_child: i32,
        _thread: u32,
        _time: u32,
    ) {
        if SHUTTING_DOWN.load(Ordering::Relaxed) {
            return;
        }
        if hwnd.is_invalid() || !unsafe { IsWindow(Some(hwnd)).as_bool() } {
            return;
        }
        let class = class_name(hwnd);
        if !class.contains("Chrome_") && !class.contains("WebView") && class != "Intermediate D3D Window"
        {
            return;
        }
        let ctx = INJECT_CTX.lock().ok().and_then(|g| g.clone());
        let Some((app, label)) = ctx else {
            return;
        };
        let _ = app.clone().run_on_main_thread(move || {
            if SHUTTING_DOWN.load(Ordering::SeqCst) {
                return;
            }
            if let Some(win) = app.get_webview_window(&label) {
                inject(&app, &win);
            }
        });
    }

    #[implement(IDropTarget)]
    struct DragDropTarget {
        hwnd: HWND,
        listener: Arc<dyn Fn(Notice) + Send + Sync>,
        enter_valid: Cell<bool>,
        logged_over: Cell<bool>,
    }

    impl DragDropTarget {
        fn new(hwnd: HWND, listener: Arc<dyn Fn(Notice) + Send + Sync>) -> Self {
            Self {
                hwnd,
                listener,
                enter_valid: Cell::new(false),
                logged_over: Cell::new(false),
            }
        }

        fn log_ole(&self, action: &str) {
            eprintln!("dumplyzer: OLE {action} {}", describe_hwnd(self.hwnd));
        }

        fn drop_format() -> FORMATETC {
            FORMATETC {
                cfFormat: CF_HDROP.0,
                ptd: ptr::null_mut(),
                dwAspect: DVASPECT_CONTENT.0,
                lindex: -1,
                tymed: TYMED_HGLOBAL.0 as u32,
            }
        }

        unsafe fn offers_files(data_obj: &windows::core::Ref<'_, IDataObject>) -> bool {
            let Some(obj) = data_obj.as_ref() else {
                return false;
            };
            let format = Self::drop_format();
            obj.QueryGetData(&format).is_ok()
        }

        unsafe fn filenames(
            data_obj: &windows::core::Ref<'_, IDataObject>,
        ) -> Option<(Vec<PathBuf>, HDROP)> {
            let format = Self::drop_format();
            let medium = data_obj.as_ref()?.GetData(&format).ok()?;
            let hdrop = HDROP(medium.u.hGlobal.0 as _);
            let count = DragQueryFileW(hdrop, 0xFFFF_FFFF, None);
            let mut paths = Vec::with_capacity(count as usize);
            for i in 0..count {
                let chars = DragQueryFileW(hdrop, i, None) as usize;
                let mut buf = vec![0u16; chars + 1];
                DragQueryFileW(hdrop, i, Some(&mut buf));
                paths.push(OsString::from_wide(&buf[..chars]).into());
            }
            Some((paths, hdrop))
        }
    }

    #[allow(non_snake_case)]
    impl IDropTarget_Impl for DragDropTarget_Impl {
        fn DragEnter(
            &self,
            pDataObj: windows::core::Ref<'_, IDataObject>,
            _grfKeyState: MODIFIERKEYS_FLAGS,
            pt: &POINTL,
            pdwEffect: *mut DROPEFFECT,
        ) -> windows::core::Result<()> {
            let mut client = POINT { x: pt.x, y: pt.y };
            let _ = unsafe { ScreenToClient(self.hwnd, &mut client) };
            let (paths, valid) = if let Some((paths, _)) =
                unsafe { DragDropTarget::filenames(&pDataObj) }
            {
                (paths, true)
            } else if unsafe { DragDropTarget::offers_files(&pDataObj) } {
                (Vec::new(), true)
            } else {
                (Vec::new(), false)
            };
            self.enter_valid.set(valid);
            self.logged_over.set(false);
            self.log_ole("DragEnter");
            if valid {
                (self.listener)(Notice::Enter(paths));
                unsafe { *pdwEffect = DROPEFFECT_COPY };
            } else {
                unsafe { *pdwEffect = DROPEFFECT_NONE };
            }
            Ok(())
        }

        fn DragOver(
            &self,
            _grfKeyState: MODIFIERKEYS_FLAGS,
            _pt: &POINTL,
            pdwEffect: *mut DROPEFFECT,
        ) -> windows::core::Result<()> {
            if self.enter_valid.get() {
                if !self.logged_over.replace(true) {
                    self.log_ole("DragOver");
                }
                (self.listener)(Notice::Over);
                unsafe { *pdwEffect = DROPEFFECT_COPY };
            } else {
                unsafe { *pdwEffect = DROPEFFECT_NONE };
            }
            Ok(())
        }

        fn DragLeave(&self) -> windows::core::Result<()> {
            if self.enter_valid.get() {
                self.log_ole("DragLeave");
                (self.listener)(Notice::Leave);
            }
            self.enter_valid.set(false);
            self.logged_over.set(false);
            Ok(())
        }

        fn Drop(
            &self,
            pDataObj: windows::core::Ref<'_, IDataObject>,
            _grfKeyState: MODIFIERKEYS_FLAGS,
            _pt: &POINTL,
            pdwEffect: *mut DROPEFFECT,
        ) -> windows::core::Result<()> {
            self.log_ole("Drop");
            if self.enter_valid.get() {
                if let Some((paths, hdrop)) = unsafe { DragDropTarget::filenames(&pDataObj) } {
                    (self.listener)(Notice::Drop(paths));
                    unsafe { DragFinish(hdrop) };
                    unsafe { *pdwEffect = DROPEFFECT_COPY };
                } else {
                    (self.listener)(Notice::Leave);
                    unsafe { *pdwEffect = DROPEFFECT_NONE };
                }
            } else {
                unsafe { *pdwEffect = DROPEFFECT_NONE };
            }
            self.enter_valid.set(false);
            self.logged_over.set(false);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FileDropNotice;

    #[test]
    fn file_drop_notice_json_shape() {
        let drop = FileDropNotice::Drop {
            paths: vec![r"C:\dumps\memory.dmp".into()],
        };
        let v = serde_json::to_value(&drop).expect("json");
        assert_eq!(v["type"], "drop");
        assert_eq!(v["paths"][0], r"C:\dumps\memory.dmp");
        let enter = serde_json::to_value(&FileDropNotice::Enter {
            paths: vec!["a.raw".into()],
        })
        .unwrap();
        assert_eq!(enter["type"], "enter");
        assert_eq!(
            serde_json::to_value(&FileDropNotice::Leave).unwrap()["type"],
            "leave"
        );
        let over = serde_json::to_value(&FileDropNotice::Over).unwrap();
        assert_eq!(over["type"], "over");
        assert!(over.get("paths").is_none());
    }
}
