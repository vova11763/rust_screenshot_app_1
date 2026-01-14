// This attribute tells the Rust compiler not to create a console window when the application starts.
// This is standard for GUI applications, including tray-only apps, to provide a cleaner user experience.
#![windows_subsystem = "windows"]

// Imports for thread-safe time tracking and atomic operations.
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::OnceLock;

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Duration};

// Import necessary items from the `windows` crate.
// The `windows` crate is the modern, Microsoft-supported way to interact with the Windows API in Rust.
use windows::{
    core::{w, PCWSTR}, // `w!` macro for UTF-16 "wide" strings, `PCWSTR` for a pointer to a constant wide string.
    Win32::{
        Foundation::{HANDLE, HMODULE, HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM, ERROR_ACCESS_DENIED},
        Graphics::Gdi::{
            BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits,
            GetMonitorInfoW, MonitorFromWindow, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
            DIB_RGB_COLORS, MONITORINFO, MONITOR_DEFAULTTOPRIMARY, SRCCOPY, GetWindowDC, ReleaseDC,
        },
        System::{
            LibraryLoader::GetModuleHandleW,
            SystemInformation::GetLocalTime,
            StationsAndDesktops::{
                CloseDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, GetUserObjectInformationW,
                OpenInputDesktop, UOI_NAME,
            },
            ProcessStatus::{EnumProcessModulesEx, GetModuleBaseNameW, LIST_MODULES_ALL},
            Threading::{
                OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
                // Critical section primitives for ThreadSafeTimeVar
                DeleteCriticalSection, EnterCriticalSection, InitializeCriticalSection,
                LeaveCriticalSection, CRITICAL_SECTION,
            },
        },
        UI::Shell::{
            Shell_NotifyIconW, NOTIFYICONDATAW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
        },
        UI::WindowsAndMessaging::{
            AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyWindow,
            DispatchMessageW, GetClassNameW, GetCursorPos, GetDesktopWindow, GetForegroundWindow,
            GetMessageW, GetSystemMetrics, GetWindowLongW, GetWindowRect,
            GetWindowTextW, GetWindowThreadProcessId, KillTimer, LoadCursorW,
            LoadIconW, MessageBoxW, PostQuitMessage, RegisterClassW, SetForegroundWindow,
            SetTimer, TrackPopupMenu, TranslateMessage, CW_USEDEFAULT, HMENU, IDC_ARROW, MSG,
            SM_CXSCREEN, SM_CYSCREEN, TPM_NONOTIFY, TPM_RETURNCMD, WM_CREATE, WM_DESTROY,
            WM_RBUTTONUP, WM_TIMER, WNDCLASSW, WS_OVERLAPPEDWINDOW, MB_ICONERROR, MB_OK,
            SPI_GETSCREENSAVERRUNNING, SystemParametersInfoW, GWL_EXSTYLE, WS_EX_TOPMOST,
            // Menu modification/checking constants and functions
            ModifyMenuW, CheckMenuItem, MF_BYCOMMAND, MF_STRING, MFS_CHECKED, MFS_UNCHECKED,
            // Hook-related imports for detecting keyboard/mouse activity
            CallNextHookEx, SetWindowsHookExW, UnhookWindowsHookEx,
            HHOOK, WH_KEYBOARD_LL, WH_MOUSE_LL,
            WM_KEYDOWN, WM_LBUTTONDOWN, WM_MBUTTONDOWN, WM_MOUSEWHEEL, WM_RBUTTONDOWN, WM_XBUTTONDOWN,
        },
    },
};

// This struct holds our configuration values.
// Easily extensible: just add more fields here and update load_config().
struct Config {
    // Directory where screenshots will be saved.
    screenshot_save_dir: String,
    // JPEG quality (1-100). Higher = better quality, larger file.
    jpeg_quality: u8,
    // If false (0), logging is disabled entirely.
    enable_logging: bool,
    // Seconds between screenshots.
    screenshot_interval_seconds: u32,
    // Skip screenshot if user idle for this many seconds.
    skip_if_inactive_seconds: u64,
}

// Global config loaded once on first access via OnceLock.
static CONFIG: OnceLock<Config> = OnceLock::new();

// Returns a reference to the global config, loading it on first call.
fn get_config() -> &'static Config {
    CONFIG.get_or_init(|| load_config())
}

// Loads config from config.ini using configparser.
// Shows an error dialog and exits if config cannot be loaded.
fn load_config() -> Config {
    // Create a new INI parser.
    let mut ini = configparser::ini::Ini::new();
    // Attempt to load the config file.
    if ini.load("config.ini").is_ok() {
        // Try to get screenshot_save_dir from [settings] section.
        if let Some(dir) = ini.get("settings", "screenshot_save_dir") {
            // Parse jpeg_quality, default to 80 if missing/invalid.
            let jpeg_quality = ini.get("settings", "jpeg_quality")
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(80);
            // Parse enable_logging: "1" means enabled, anything else means disabled.
            let enable_logging = ini.get("settings", "enable_logging")
                .map(|s| s.trim() == "1")
                .unwrap_or(true);
            // Parse screenshot_interval_seconds, default to SCREENSHOT_EVERY_N_SECONDS.
            let screenshot_interval_seconds = ini.get("settings", "screenshot_interval_seconds")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(SCREENSHOT_EVERY_N_SECONDS as u32);
            // Parse skip_if_inactive_seconds, default to FACTORED_IN__LAST_INPUT_ACTIVITY.
            let skip_if_inactive_seconds = ini.get("settings", "skip_if_inactive_seconds")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(FACTORED_IN__LAST_INPUT_ACTIVITY as u64);
            return Config {
                screenshot_save_dir: dir,
                jpeg_quality,
                enable_logging,
                screenshot_interval_seconds,
                skip_if_inactive_seconds,
            };
        }
    }
    // Config file not found or invalid - show error and exit.
    show_error_dialog("Failed to load config.ini.\n\nPlease ensure config.ini exists and contains:\n[settings]\nscreenshot_save_dir = C:/path/to/screenshots");
    std::process::exit(1);
}

// Shows a Win32 MessageBox with the error message.
fn show_error_dialog(message: &str) {
    unsafe {
        // Convert message to wide string for Win32 API.
        let mut wide_msg: Vec<u16> = message.encode_utf16().collect();
        wide_msg.push(0);
        MessageBoxW(None, PCWSTR(wide_msg.as_ptr()), w!("Screenshotter Error"), MB_ICONERROR | MB_OK);
    }
}

const WM_TRAYICON: u32 = 0x8000 + 1;
const MENU_ITEM_HELP_ID: usize = 1001;
const MENU_ITEM_EXIT_ID: usize = 1002;
// Pause menu item (we'll update its label dynamically)
const MENU_ITEM_PAUSE_ID: usize = 1003;
const SCREENSHOT_TIMER_ID: usize = 1;

const SCREENSHOT_EVERY_N_SECONDS: usize = 60; // 60 seconds
const FACTORED_IN__LAST_INPUT_ACTIVITY: usize = 60 * 3; // 180 seconds

// Pause duration in seconds (3 minutes)
const PAUSE_DURATION: u64 = 2 * 60;
// Pause duration in minutes, derived from the above constant
const PAUSE_DURATION_MINUTES: u64 = PAUSE_DURATION / 60;

// Precomputed null-terminated UTF-16 buffer for the pause menu label.
// This allows passing a PCWSTR pointer to Win32 APIs without re-encoding every time.
static PAUSE_MENU_LABEL_WIDE: OnceLock<Vec<u16>> = OnceLock::new();

// Helper to get the pause menu label wide buffer.
fn get_pause_menu_label_wide() -> &'static Vec<u16> {
    PAUSE_MENU_LABEL_WIDE.get_or_init(|| {
        format!("Pause [{}m]", PAUSE_DURATION_MINUTES)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    })
}

// Atomic storage for pause end time expressed as UNIX epoch seconds.
// 0 means no pause end time set (i.e. not paused).
static PAUSE_END_TIME: AtomicU64 = AtomicU64::new(0);

static mut POPUP_MENU: HMENU = HMENU(std::ptr::null_mut());
// Global handles for low-level keyboard and mouse hooks.
static mut KEYBOARD_HOOK: HHOOK = HHOOK(std::ptr::null_mut());
static mut MOUSE_HOOK: HHOOK = HHOOK(std::ptr::null_mut());

// ==============================================================================
// ThreadSafeTimeVar: A thread-safe wrapper around SystemTime using Win32 CRITICAL_SECTION.
// ==============================================================================
pub struct ThreadSafeTimeVar {
    // The actual SystemTime value, wrapped for interior mutability.
    value: UnsafeCell<SystemTime>,
    // Win32 CRITICAL_SECTION for synchronization.
    cs: UnsafeCell<CRITICAL_SECTION>,
    // Tracks whether the critical section has been initialized.
    initialized: AtomicBool,
}

impl ThreadSafeTimeVar {
    // Creates a new ThreadSafeTimeVar. Suitable for use in a static context.
    pub const fn new() -> Self {
        Self {
            // Initial value; will be set properly on first use.
            value: UnsafeCell::new(SystemTime::UNIX_EPOCH),
            // The CRITICAL_SECTION must be initialized before use.
            cs: UnsafeCell::new(CRITICAL_SECTION {
                DebugInfo: std::ptr::null_mut(),
                LockCount: 0,
                RecursionCount: 0,
                OwningThread: HANDLE(std::ptr::null_mut()),
                LockSemaphore: HANDLE(std::ptr::null_mut()),
                SpinCount: 0,
            }),
            initialized: AtomicBool::new(false),
        }
    }

    // Ensures the critical section is initialized exactly once.
    fn ensure_initialized(&self) {
        if !self.initialized.load(AtomicOrdering::Acquire) {
            unsafe {
                // Initialize the critical section (must only be called once).
                InitializeCriticalSection(self.cs.get());
            }
            // Mark as initialized with Release ordering.
            self.initialized.store(true, AtomicOrdering::Release);
        }
    }

    // Safely sets the SystemTime value.
    pub fn set(&self, val: SystemTime) {
        self.ensure_initialized();
        unsafe {
            // Acquire the lock.
            EnterCriticalSection(self.cs.get());
            // Write the value.
            *self.value.get() = val;
            // Release the lock.
            LeaveCriticalSection(self.cs.get());
        }
    }

    // Safely gets the SystemTime value.
    pub fn get(&self) -> SystemTime {
        self.ensure_initialized();
        unsafe {
            // Acquire the lock.
            EnterCriticalSection(self.cs.get());
            // Read the value.
            let result = *self.value.get();
            // Release the lock.
            LeaveCriticalSection(self.cs.get());
            result
        }
    }
}

// Clean up the CRITICAL_SECTION when the ThreadSafeTimeVar is dropped.
impl Drop for ThreadSafeTimeVar {
    fn drop(&mut self) {
        if self.initialized.load(AtomicOrdering::Acquire) {
            unsafe {
                DeleteCriticalSection(self.cs.get());
            }
        }
    }
}

// Tell Rust this type is safe to share across threads (we handle sync via CRITICAL_SECTION).
unsafe impl Send for ThreadSafeTimeVar {}
unsafe impl Sync for ThreadSafeTimeVar {}

// The global, thread-safe variable to store the timestamp of the last user input.
static LAST_INPUT_TIME: ThreadSafeTimeVar = ThreadSafeTimeVar::new();
// Tracks when we last logged input (to avoid clogging the log).
static LAST_LOGGED_INPUT_TIME: ThreadSafeTimeVar = ThreadSafeTimeVar::new();

// We store the pause end time as UNIX epoch seconds in `PAUSE_END_TIME`.
// This is a simple, lock-free representation suitable for our needs.

fn main() {
    let _ = fs::remove_file("logfile.txt");
    log_message("Application starting...");
    // Load config (triggers OnceLock initialization).
    let config = get_config();
    log_message(&format!("Loaded config. Save directory: {}", &config.screenshot_save_dir));
    if !Path::new(&config.screenshot_save_dir).is_dir() {
        show_error_dialog(&format!("Screenshot directory not found:\n{}\n\nPlease create the directory or update config.ini.", &config.screenshot_save_dir));
        return;
    }

    unsafe {
        let instance = GetModuleHandleW(PCWSTR::null()).unwrap();
        let class_name = w!("RustScreenShotTrayAppClass");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance.into(),
            lpszClassName: class_name,
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap(),
            ..Default::default()
        };
        let atom = RegisterClassW(&wc);
        if atom == 0 {
            panic!("Could not register window class");
        }
        let hwnd = CreateWindowExW(
            Default::default(), class_name, w!("Simple Tray App"), WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
            None, None, Some(instance.into()), None,
        ).unwrap();
        add_tray_icon(hwnd);
        let mut msg: MSG = Default::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        remove_tray_icon(hwnd);
        log_message("Application shutting down.");
    }
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => 
        {
            // Create the popup menu for the tray icon
            POPUP_MENU = CreatePopupMenu().unwrap();
            // Add a Help item
            AppendMenuW(POPUP_MENU, Default::default(), MENU_ITEM_HELP_ID, w!("Help")).unwrap();
            // Add the Pause item with duration from PAUSE_DURATION constant
            // Use the precomputed null-terminated UTF-16 buffer and pass a PCWSTR pointer.
            let _ = AppendMenuW(
                POPUP_MENU,
                Default::default(),
                MENU_ITEM_PAUSE_ID,
                PCWSTR(get_pause_menu_label_wide().as_ptr()),
            );
            // Add an Exit item
            AppendMenuW(POPUP_MENU, Default::default(), MENU_ITEM_EXIT_ID, w!("Exit")).unwrap();
            // Set a recurring timer using interval from config.
            SetTimer(Some(hwnd), SCREENSHOT_TIMER_ID, get_config().screenshot_interval_seconds * 1000, None);

            // Initialize the last input time to now.
            LAST_INPUT_TIME.set(SystemTime::now());

            // Install the low-level keyboard and mouse hooks to track user activity.
            let h_instance = Some(HINSTANCE(GetModuleHandleW(PCWSTR::null()).unwrap().0));
            KEYBOARD_HOOK = SetWindowsHookExW(WH_KEYBOARD_LL, Some(low_level_keyboard_proc), h_instance, 0).unwrap();
            MOUSE_HOOK = SetWindowsHookExW(WH_MOUSE_LL, Some(low_level_mouse_proc), h_instance, 0).unwrap();
            log_message("Installed keyboard and mouse hooks for activity tracking.");

            LRESULT(0)
        }
        WM_TRAYICON => {
            if lparam.0 as u32 == WM_RBUTTONUP 
            {
                // Before showing the menu, update pause item label/check state
                update_pause_menu_item();

                let mut point = POINT::default();
                let _ = GetCursorPos(&mut point);
                let _ = SetForegroundWindow(hwnd);
                // Show the popup menu and wait for a command
                let cmd = TrackPopupMenu(POPUP_MENU, TPM_RETURNCMD | TPM_NONOTIFY, point.x, point.y, Some(0), hwnd, None);
                if cmd.0 != 0 
                {
                    handle_menu_click(hwnd, cmd.0 as usize);
                }
            }
            LRESULT(0)
        }
        WM_TIMER => 
        {
            // Screenshot timer fired (every minute)
            if wparam.0 == SCREENSHOT_TIMER_ID 
            {
                // Load pause end time (0 means not paused)
                let end_unix = PAUSE_END_TIME.load(Ordering::Relaxed);

                if end_unix != 0
                {
                    // If pause is scheduled, check if it has expired
                    let now_unix = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if now_unix >= end_unix
                    {
                        // Pause expired -> clear pause
                        PAUSE_END_TIME.store(0, Ordering::Relaxed);
                        log_message("Pause period ended - resuming screenshots.");
                        // fall through to take screenshot this tick
                    }
                    else
                    {
                        // Still paused, skip taking screenshot
                        return LRESULT(0);
                    }
                }
                // If not paused (end_unix == 0) take a screenshot
                if PAUSE_END_TIME.load(Ordering::Relaxed) == 0
                {
                    std::thread::spawn(move || 
                    {
                        if let Err(e) = take_screenshot() 
                        {
                            log_message(&format!("Failed to take screenshot: {}", e));
                        }
                    });
                }
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            let _ = KillTimer(Some(hwnd), SCREENSHOT_TIMER_ID);
            // Unhook the low-level keyboard and mouse hooks.
            let _ = UnhookWindowsHookEx(KEYBOARD_HOOK);
            let _ = UnhookWindowsHookEx(MOUSE_HOOK);
            log_message("Unhooked keyboard and mouse hooks.");
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe fn add_tray_icon(hwnd: HWND) {
    let instance = GetModuleHandleW(PCWSTR::null()).unwrap();
    let icon_handle = LoadIconW(Some(instance.into()), PCWSTR(1 as *const u16)).unwrap();
    let mut nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd, uID: 1, uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
        uCallbackMessage: WM_TRAYICON, hIcon: icon_handle, ..Default::default()
    };
    let tooltip = w!("Simplistic Rust Screenshotter App");
    nid.szTip[..tooltip.as_wide().len()].copy_from_slice(tooltip.as_wide());
    let _ = Shell_NotifyIconW(NIM_ADD, &mut nid);
}

unsafe fn remove_tray_icon(hwnd: HWND) {
    let nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd, uID: 1, ..Default::default()
    };
    let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
}

// Update the pause menu item's text and check state based on the current pause status.
// This function builds a wide (UTF-16) label and uses ModifyMenuW / CheckMenuItem
// so the context menu reflects the remaining pause time and shows a checkmark
// when paused.
unsafe fn update_pause_menu_item()
{
    // Read the pause end time and compute paused state (end_unix > now => paused)
    let end_unix = PAUSE_END_TIME.load(Ordering::Relaxed);
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let is_paused = end_unix > now_unix;

    // Prepare and apply the menu label and check state based on paused/not-paused.
    if is_paused
    {
        // If paused, compute remaining seconds until pause end and build a dynamic label.
        let remaining = if end_unix > now_unix { end_unix - now_unix } else { 0 };
        // Create a label like: "Paused (+179s)\0"
        let label = format!("Paused (+{}s)\0", remaining);
        let mut v: Vec<u16> = label.encode_utf16().collect();
        // Ensure null-termination
        if *v.last().unwrap_or(&0) != 0 { v.push(0); }

        // Modify menu item text using the temporary buffer
        let _ = ModifyMenuW(
            POPUP_MENU,
            MENU_ITEM_PAUSE_ID as u32,
            MF_BYCOMMAND | MF_STRING,
            MENU_ITEM_PAUSE_ID,
            PCWSTR(v.as_ptr()),
        );

        // Build raw flags and set checked state (extract numeric inner values with .0)
        let flags_raw: u32 = MF_BYCOMMAND.0 | MFS_CHECKED.0;
        let _ = CheckMenuItem(POPUP_MENU, MENU_ITEM_PAUSE_ID as u32, flags_raw);
    }
    else
    {
        // Not paused - use precomputed null-terminated wide buffer to avoid re-encoding
        let _ = ModifyMenuW(
            POPUP_MENU,
            MENU_ITEM_PAUSE_ID as u32,
            MF_BYCOMMAND | MF_STRING,
            MENU_ITEM_PAUSE_ID,
            PCWSTR(get_pause_menu_label_wide().as_ptr()),
        );

        // Build raw flags and set unchecked state
        let flags_raw: u32 = MF_BYCOMMAND.0 | MFS_UNCHECKED.0;
        let _ = CheckMenuItem(POPUP_MENU, MENU_ITEM_PAUSE_ID as u32, flags_raw);
    }
}

unsafe fn handle_menu_click(hwnd: HWND, item_id: usize) 
{
    match item_id 
    {
        // Show help message
        MENU_ITEM_HELP_ID => 
        {
            MessageBoxW(Some(hwnd), w!("This is a simple sreenshotter application..."), w!("Help"), MB_OK);
        }

        // Toggle Pause/Unpause when the Pause menu item is clicked
        MENU_ITEM_PAUSE_ID => 
        {
            // Log click
            log_message("'Pause' menu item clicked.");

            // Check current pause end time. 0 == not paused
            let end_unix = PAUSE_END_TIME.load(Ordering::Relaxed);
            if end_unix != 0
            {
                // Currently paused -> unpause
                PAUSE_END_TIME.store(0, Ordering::Relaxed);
                log_message("Unpaused by user.");
            }
            else
            {
                // Not paused -> set the pause end time to now + duration
                let end_unix = SystemTime::now()
                    .checked_add(Duration::from_secs(PAUSE_DURATION))
                    .unwrap_or(SystemTime::now())
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                PAUSE_END_TIME.store(end_unix, Ordering::Relaxed);
                log_message(&format!("Paused for {} minutes.", PAUSE_DURATION / 60));
            }
        }

        // Exit the application
        MENU_ITEM_EXIT_ID => 
        {
            let _ = DestroyWindow(hwnd);
        }

        _ => {}
    }
}

unsafe fn is_input_blocked() -> bool {
    log_message("[SSC/LLC 1]: Checking foreground window for screensaver class...");
    let hwnd_foreground = GetForegroundWindow();
    if !hwnd_foreground.is_invalid() 
    {
        let mut class_name_buffer = [0u16; 256];
        let length = GetClassNameW(hwnd_foreground, &mut class_name_buffer);
        if length > 0
        {
            let class_name = String::from_utf16_lossy(&class_name_buffer[..length as usize]);
            log_message(&format!("Foreground window class name: '{}'", class_name));
            if class_name == "Windows.UI.Core.CoreWindow" {
                return additional_screen_saver_investigator(hwnd_foreground);
            }
            if class_name.contains("WindowsScreenSaverClass") || class_name.contains("ScreenSaverClass") || class_name == "OpenGL" {
                return true;
            }
        }
        else
        {
            log_message(&format!("GetForegrundWindow() -> GetWindowClassName() returned zero-length name. Probably screensaver."));
            return true;
        }
    }
    else
    {
        log_message(&format!("GetForegroundWindow() returned null. Probably screensaver."));
        return true;
    }
    
    log_message("[SSC/LLC 2]: Checking for active screensaver...");
    let mut is_screensaver_running: u32 = 0;
    let _ = SystemParametersInfoW(SPI_GETSCREENSAVERRUNNING, 0, Some(&mut is_screensaver_running as *mut _ as *mut std::ffi::c_void), Default::default());
    if is_screensaver_running != 0 {
        return true;
    }

    log_message("[SSC/LLC 3]: Checking for locked desktop...");
    let h_desktop_result = OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS);
    match h_desktop_result {
        Ok(h_desktop) => {
            let mut name_buffer = [0u16; 256];
            let mut length_needed = 0;
            if GetUserObjectInformationW(HANDLE(h_desktop.0), UOI_NAME, Some(name_buffer.as_mut_ptr().cast()), name_buffer.len() as u32, Some(&mut length_needed)).is_ok() {
                let desktop_name = String::from_utf16_lossy(&name_buffer[..length_needed as usize / 2]);
                if !desktop_name.trim_end_matches('\0').eq_ignore_ascii_case("Default") {
                    let _ = CloseDesktop(h_desktop);
                    return true;
                }
            }
            let _ = CloseDesktop(h_desktop);
            false
        }
        Err(e) => e.code() == ERROR_ACCESS_DENIED.to_hresult(),
    }
}

unsafe fn additional_screen_saver_investigator(hwnd: HWND) -> bool {
    log_message("[SSC/LLC 5]: Analyzing potentially suspicious window (class: Windows.UI.Core.CoreWindow) ...");
    let mut title_buffer = [0u16; 512];
    let title_len = GetWindowTextW(hwnd, &mut title_buffer);
    if title_len > 0 {
        let title = String::from_utf16_lossy(&title_buffer[..title_len as usize]);
        log_message(&format!("[Investigator] Window Title: '{}'", title));
    } else {
        log_message("[Investigator] Window Title: (empty)");
    }

    // --- Get and Log Window Geometry ---
    let mut window_rect = RECT::default();
    let mut is_fullscreen = false;
    if GetWindowRect(hwnd, &mut window_rect).is_ok() {
        let width = window_rect.right - window_rect.left;
        let height = window_rect.bottom - window_rect.top;
        log_message(&format!("[Investigator] Window Size: {}x{}", width, height));
        
        let primary_monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTOPRIMARY);
        let mut monitor_info = MONITORINFO::default();
        monitor_info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        
        if GetMonitorInfoW(primary_monitor, &mut monitor_info).as_bool() {
            let covers_width = window_rect.left <= monitor_info.rcMonitor.left && 
                              window_rect.right >= monitor_info.rcMonitor.right;
            let covers_height = window_rect.top <= monitor_info.rcMonitor.top && 
                               window_rect.bottom >= monitor_info.rcMonitor.bottom;
            is_fullscreen = covers_width && covers_height;
            log_message(&format!("[Investigator] Is Fullscreen: {}", is_fullscreen));
        }
    }

    // --- Get and Log Window Styles ---
    let extended_styles = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
    let is_topmost = (extended_styles & WS_EX_TOPMOST.0) != 0;
    log_message(&format!("[Investigator] Is TopMost: {}", is_topmost));

    // --- Get Process Info and Check for LockApp.exe ---
    let mut process_id: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut process_id));
    let mut process_name = String::new();
    if process_id != 0 {
        log_message(&format!("[Investigator] Process ID: {}", process_id));
        let process_handle_result = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process_id);
        if let Ok(process_handle) = process_handle_result {
            let mut module_handles = [HMODULE::default(); 1];
            let mut bytes_needed: u32 = 0;
            if EnumProcessModulesEx(process_handle, module_handles.as_mut_ptr(), std::mem::size_of_val(&module_handles) as u32, &mut bytes_needed, LIST_MODULES_ALL).is_ok() {
                let mut process_name_buffer = [0u16; 256];
                let name_len = GetModuleBaseNameW(process_handle, Some(module_handles[0]), &mut process_name_buffer);
                if name_len > 0 {
                    process_name = String::from_utf16_lossy(&process_name_buffer[..name_len as usize]);
                    log_message(&format!("[Investigator] Process Name: '{}'", process_name));
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(process_handle);
        }
    }

    // --- Final Verdict ---
    if process_name.eq_ignore_ascii_case("LockApp.exe") {
        log_message("[Investigator] VERDICT: Input is BLOCKED (Lock Screen process name)");
        return true;
    }
    if is_fullscreen && is_topmost {
        log_message("[Investigator] VERDICT: Input is BLOCKED (Fullscreen and TopMost window)");
        return true;
    }

    log_message("[Investigator] VERDICT: Input appears AVAILABLE");
    false
}

use jpeg_encoder::{Encoder, ColorType};

fn take_screenshot() -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { is_input_blocked() } {
        log_message("Screen is locked or screensaver is active; skipping screenshot.");
        return Ok(());
    }

    // Check if the user has been idle for too long => skip screenshot.
    let last_input = LAST_INPUT_TIME.get();
    let elapsed = SystemTime::now().duration_since(last_input).unwrap_or_default();
    // Use skip_if_inactive_seconds from config.
    let idle_threshold = get_config().skip_if_inactive_seconds;
    if elapsed.as_secs() > idle_threshold {
        log_message(&format!(
            "User idle for {}s (threshold {}s) — skipping screenshot.",
            elapsed.as_secs(),
            idle_threshold
        ));
        return Ok(());
    }

    if !Path::new(&get_config().screenshot_save_dir).is_dir() {
        log_message(&format!("Screenshot directory '{}' not found, skipping screenshot.", &get_config().screenshot_save_dir));
        return Ok(());
    }
    log_message("Taking screenshot...");
    unsafe {
        let h_wnd_desktop = GetDesktopWindow();
        let h_dc = GetWindowDC(Some(h_wnd_desktop));
        let h_mem_dc = CreateCompatibleDC(Some(h_dc));
        if h_mem_dc.is_invalid() {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Failed to create memory DC")));
        }
        let width = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);
        let h_bitmap = CreateCompatibleBitmap(h_dc, width, height);
        if h_bitmap.is_invalid() {
            let _ = DeleteDC(h_mem_dc);
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Failed to create bitmap")));
        }
        let h_old_bitmap = SelectObject(h_mem_dc, h_bitmap.into());
        BitBlt(h_mem_dc, 0, 0, width, height, Some(h_dc), 0, 0, SRCCOPY)?;
        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width, biHeight: -height, biPlanes: 1, biBitCount: 32,
                biCompression: BI_RGB.0 as u32, ..Default::default()
            }, ..Default::default()
        };
        let mut bgra_buffer: Vec<u8> = vec![0; (width * height * 4) as usize];
        GetDIBits(h_dc, h_bitmap, 0, height as u32, Some(bgra_buffer.as_mut_ptr() as *mut _), &mut bmi, DIB_RGB_COLORS);
        let mut rgb_buffer: Vec<u8> = Vec::with_capacity((width * height * 3) as usize);
        for chunk in bgra_buffer.chunks_exact(4) {
            rgb_buffer.push(chunk[2]);
            rgb_buffer.push(chunk[1]);
            rgb_buffer.push(chunk[0]);
        }
        let st = GetLocalTime();
        let subfolder = format!("{:04}-{:02}-{:02}", st.wYear, st.wMonth, st.wDay);
        let filename = format!("{:04}-{:02}-{:02}.{:02}-{:02}-{:02}.jpg", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        let full_path = Path::new(&get_config().screenshot_save_dir).join(&subfolder).join(&filename);
        if let Some(parent_dir) = full_path.parent() {
            fs::create_dir_all(parent_dir)?;
        }
        // Create JPEG encoder using quality from config.
        let encoder = Encoder::new(File::create(&full_path)?, get_config().jpeg_quality);
        encoder.encode(&rgb_buffer, width as u16, height as u16, ColorType::Rgb)?;
        SelectObject(h_mem_dc, h_old_bitmap);
        let _ = DeleteObject(h_bitmap.into());
        let _ = DeleteDC(h_mem_dc);
        ReleaseDC(Some(h_wnd_desktop), h_dc);
        log_message(&format!("Screenshot saved: {}", full_path.display()));
    }
    Ok(())
}

// ==============================================================================
// Low-level hook procedures for tracking keyboard/mouse activity.
// These update LAST_INPUT_TIME whenever input is detected.
// ==============================================================================

// Records user activity by updating LAST_INPUT_TIME and logging (throttled).
fn record_activity(event_details: &str) {
    // Get current time.
    let now = SystemTime::now();
    // Get elapsed since last input.
    let last_input_time = LAST_INPUT_TIME.get();
    let elapsed = now.duration_since(last_input_time).unwrap_or_default();
    // Get elapsed since last logged input.
    let last_logged = LAST_LOGGED_INPUT_TIME.get();
    let logged_elapsed = now.duration_since(last_logged).unwrap_or_default();

    // Log only if >30 seconds have passed since last log (to avoid clogging).
    if logged_elapsed.as_secs() > 30 {
        let message = format!("{} (+{}s)", event_details, elapsed.as_secs());
        log_message(&message);
        // Update last logged time.
        LAST_LOGGED_INPUT_TIME.set(now);
    }

    // Always update last input time.
    LAST_INPUT_TIME.set(now);
}

// Low-level keyboard hook procedure.
unsafe extern "system" fn low_level_keyboard_proc(
    n_code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // If n_code >= 0, we can process the message.
    if n_code >= 0 {
        // We care about key-down events.
        if wparam.0 as u32 == WM_KEYDOWN {
            // Record this activity with event details.
            record_activity("[KB]: dn");
        }
    }
    // Pass the hook information to the next hook in the chain.
    CallNextHookEx(None, n_code, wparam, lparam)
}

// Low-level mouse hook procedure.
unsafe extern "system" fn low_level_mouse_proc(
    n_code: i32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // If n_code >= 0, we can process the message.
    if n_code >= 0 {
        // Check for various mouse button/scroll events.
        let msg = wparam.0 as u32;
        if msg == WM_LBUTTONDOWN
            || msg == WM_RBUTTONDOWN
            || msg == WM_MBUTTONDOWN
            || msg == WM_MOUSEWHEEL
            || msg == WM_XBUTTONDOWN
        {
            // Record this activity with event details.
            record_activity("[M]: click");
        }
    }
    // Pass the hook information to the next hook in the chain.
    CallNextHookEx(None, n_code, wparam, lparam)
}

fn log_message(message: &str) 
{
    // If logging is disabled in config, do nothing.
    if !get_config().enable_logging {
        return;
    }

    const LOG_FILE: &str = "logfile.txt";
    const MAX_SIZE: u64 = 100 * 1024; // 100 KB

    let st = unsafe { GetLocalTime() };
    let timestamp = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    if let Ok(metadata) = fs::metadata(LOG_FILE) 
    {
        if metadata.len() > MAX_SIZE 
        {
            if let Ok(mut file) = OpenOptions::new().write(true).truncate(true).create(true).open(LOG_FILE) 
            {
                let _ = writeln!(file, "[{}] Log file erased after exceeding {}kb. Resuming logging.", timestamp, MAX_SIZE / 1024);
            }
        }
    }

    if let Ok(mut file) = OpenOptions::new().create(true).write(true).append(true).open(LOG_FILE) 
    {
        let _ = writeln!(file, "[{}] {}", timestamp, message);
    }
}
