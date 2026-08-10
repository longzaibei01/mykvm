#![cfg(target_os = "windows")]

use std::{
    ptr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use crate::shared_input::{
    mouse_button_mask, GestureAction, GesturePhase, InputCommand, MouseButton,
};

/// Explains a refused button/key injection, throttled to one line per 10s.
///
/// Windows blocks `SendInput` from a standard-user process into an elevated or
/// uiAccess foreground window (Task Manager — which ships `uiAccess="true"` — a
/// UAC-elevated app, etc.) with `ERROR_ACCESS_DENIED`; the events are dropped
/// silently, which reads to the user as "remote control just stopped" even
/// though MyKVM is still running. Cursor MOVE keeps working because it goes
/// through SetCursorPos, not SendInput — so only clicks and keys die, exactly
/// the reported symptom. Surface it instead of failing mutely (this replaces a
/// leftover per-event debug write to C:\ProgramData\MyKVM\*.txt).
fn note_injection_refused(kind: &str, error: u32) {
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    static LAST_WARN: OnceLock<Mutex<Instant>> = OnceLock::new();
    let cell = LAST_WARN.get_or_init(|| Mutex::new(Instant::now() - Duration::from_secs(60)));
    if let Ok(mut last) = cell.lock() {
        if last.elapsed() < Duration::from_secs(10) {
            return;
        }
        *last = Instant::now();
    }

    if error == ERROR_ACCESS_DENIED {
        log::warn!(
            "injected {kind} refused by Windows (ERROR_ACCESS_DENIED): an elevated or \
             uiAccess window (e.g. Task Manager, a UAC-elevated app) has focus. A \
             standard-user MyKVM cannot hook or inject into higher-privilege windows — \
             restart MyKVM as administrator (Settings) on this machine to control them."
        );
    } else {
        log::warn!("injected {kind} was refused: SendInput failed with error {error}");
    }
}

pub fn inject_command(command: &InputCommand, pressed_keys: &mut Vec<u16>, button_mask: &mut u64) {
    if matches!(command, InputCommand::ReleaseAll) {
        release_pressed_inputs(pressed_keys, button_mask);
        return;
    }

    track_pressed_inputs(command, pressed_keys, button_mask);
    inject_command_without_tracking(command);
}

pub fn release_pressed_inputs_on_fresh_input_desktop(
    pressed_keys: &mut Vec<u16>,
    button_mask: &mut u64,
) -> Result<String, String> {
    let mut desktop = DesktopAttachment::new();
    let name = desktop.attach_current_input_desktop()?;
    release_pressed_inputs(pressed_keys, button_mask);
    Ok(name)
}

pub fn track_pressed_inputs(
    command: &InputCommand,
    pressed_keys: &mut Vec<u16>,
    button_mask: &mut u64,
) {
    match *command {
        InputCommand::MouseButton { button, down, .. } => {
            if down {
                *button_mask |= mouse_button_mask(button);
            } else {
                *button_mask &= !mouse_button_mask(button);
            }
        }
        InputCommand::Key { key_code, down } => {
            if down {
                if !pressed_keys.contains(&key_code) {
                    pressed_keys.push(key_code);
                }
            } else {
                pressed_keys.retain(|pressed| *pressed != key_code);
            }
        }
        _ => {}
    }
}

pub fn inject_command_without_tracking(command: &InputCommand) {
    match *command {
        InputCommand::MouseMove { x, y, .. } => inject_mouse_move(x, y, None),
        InputCommand::MouseButton { button, down, x, y } => inject_mouse_button(button, down, x, y),
        InputCommand::Scroll { delta_x, delta_y } => inject_scroll(delta_x, delta_y),
        InputCommand::PreciseScroll {
            delta_x,
            delta_y,
            phase,
            momentum_phase,
        } => inject_precise_scroll(delta_x, delta_y, phase, momentum_phase),
        InputCommand::Swipe {
            delta_x,
            delta_y,
            phase,
        } => inject_swipe(delta_x, delta_y, phase),
        InputCommand::Pinch {
            magnification,
            phase,
            x,
            y,
        } => inject_pinch(magnification, phase, x, y),
        InputCommand::GestureAction { action } => inject_gesture_action(action),
        InputCommand::Key { key_code, down } => inject_key(key_code, down),
        InputCommand::ReleaseAll => {}
        InputCommand::SecureAttention => {
            let _ = send_secure_attention();
        }
    }
}

fn inject_gesture_action(action: GestureAction) {
    match action {
        GestureAction::TaskView => inject_key_chord(&[0x5B, 0x09]),
        GestureAction::ShowDesktop => inject_key_chord(&[0x5B, 0x44]),
    }
}

pub fn release_pressed_inputs(pressed_keys: &mut Vec<u16>, button_mask: &mut u64) {
    let keys = std::mem::take(pressed_keys);
    for key_code in keys.into_iter().rev() {
        inject_key(key_code, false);
    }

    for button in [MouseButton::Left, MouseButton::Right, MouseButton::Middle] {
        let mask = mouse_button_mask(button);
        if *button_mask & mask != 0 {
            inject_mouse_button(button, false, 0, 0);
        }
    }
    *button_mask = 0;
}

pub struct DesktopAttachment {
    desktop: windows_sys::Win32::System::StationsAndDesktops::HDESK,
    name: String,
}

impl DesktopAttachment {
    pub fn new() -> Self {
        Self {
            desktop: ptr::null_mut(),
            name: String::new(),
        }
    }

    pub fn attach_current_input_desktop(&mut self) -> Result<String, String> {
        use windows_sys::Win32::System::StationsAndDesktops::{
            CloseDesktop, OpenInputDesktop, SetThreadDesktop, DESKTOP_CREATEWINDOW,
            DESKTOP_JOURNALPLAYBACK, DESKTOP_JOURNALRECORD, DESKTOP_READOBJECTS,
            DESKTOP_SWITCHDESKTOP, DESKTOP_WRITEOBJECTS,
        };

        unsafe {
            // DESKTOP_JOURNALPLAYBACK is REQUIRED for SendInput to be accepted on
            // the attached desktop: without it the worker's synthetic clicks/keys
            // are refused with ERROR_ACCESS_DENIED (only mouse-move, which uses a
            // different path, slips through). This is why the SYSTEM worker could
            // move the cursor on the lock screen but not click or type.
            let desktop = OpenInputDesktop(
                0,
                0,
                DESKTOP_READOBJECTS
                    | DESKTOP_WRITEOBJECTS
                    | DESKTOP_SWITCHDESKTOP
                    | DESKTOP_CREATEWINDOW
                    | DESKTOP_JOURNALPLAYBACK
                    | DESKTOP_JOURNALRECORD,
            );
            if desktop.is_null() {
                return Err("OpenInputDesktop failed".into());
            }

            let name = desktop_name(desktop).unwrap_or_else(|| "<unknown>".into());

            // Always re-attach to the freshly opened input desktop. Caching by
            // name is unsafe: a secure-desktop transition (e.g. clicking
            // "I forgot my PIN" / "Reset password" on the lock screen) switches
            // to a DIFFERENT desktop object that often carries the SAME name
            // ("Winlogon"). A name-equality cache would then skip SetThreadDesktop
            // and leave the worker bound to the old, now-inactive desktop, so
            // clicks/keys silently stop until the worker restarts. OpenInputDesktop
            // is already called every time here, so re-attaching is essentially
            // free.
            if SetThreadDesktop(desktop) == 0 {
                let _ = CloseDesktop(desktop);
                return Err(format!("SetThreadDesktop failed for {name}"));
            }

            if !self.desktop.is_null() {
                let _ = CloseDesktop(self.desktop);
            }
            self.desktop = desktop;
            self.name = name.clone();
            return Ok(name);
        }
    }
}

unsafe fn desktop_name(
    desktop: windows_sys::Win32::System::StationsAndDesktops::HDESK,
) -> Option<String> {
    use windows_sys::Win32::System::StationsAndDesktops::{GetUserObjectInformationW, UOI_NAME};

    let mut needed = 0_u32;
    let mut buffer = [0_u16; 256];
    let ok = GetUserObjectInformationW(
        desktop as _,
        UOI_NAME,
        buffer.as_mut_ptr() as *mut _,
        (buffer.len() * std::mem::size_of::<u16>()) as u32,
        &mut needed,
    ) != 0;
    if !ok || needed == 0 {
        return None;
    }
    let len = buffer
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..len]))
}

impl Drop for DesktopAttachment {
    fn drop(&mut self) {
        if !self.desktop.is_null() {
            unsafe {
                let _ = windows_sys::Win32::System::StationsAndDesktops::CloseDesktop(self.desktop);
            }
        }
    }
}

pub fn inject_mouse_move(x: i32, y: i32, _drag_button: Option<MouseButton>) {
    use windows_sys::Win32::UI::{
        Input::KeyboardAndMouse::{
            SendInput, INPUT, INPUT_0, INPUT_MOUSE, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_MOVE,
            MOUSEEVENTF_VIRTUALDESK, MOUSEINPUT,
        },
        WindowsAndMessaging::{
            GetSystemMetrics, SetCursorPos, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN,
            SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
        },
    };

    unsafe {
        let virtual_x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let virtual_y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let virtual_width = GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1);
        let virtual_height = GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1);
        let normalized_x =
            ((x - virtual_x) as i64 * 65_535 / (virtual_width - 1).max(1) as i64) as i32;
        let normalized_y =
            ((y - virtual_y) as i64 * 65_535 / (virtual_height - 1).max(1) as i64) as i32;
        let input = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: normalized_x.clamp(0, 65_535),
                    dy: normalized_y.clamp(0, 65_535),
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        if SendInput(1, &input, std::mem::size_of::<INPUT>() as i32) == 0 {
            let _ = SetCursorPos(x, y);
        }
    }
}

pub fn inject_mouse_button(button: MouseButton, down: bool, x: i32, y: i32) {
    use windows_sys::Win32::UI::{
        Input::KeyboardAndMouse::{
            SendInput, INPUT, INPUT_0, INPUT_MOUSE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
            MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
            MOUSEEVENTF_XDOWN, MOUSEEVENTF_XUP, MOUSEINPUT,
        },
        WindowsAndMessaging::{XBUTTON1, XBUTTON2},
    };

    if x != 0 || y != 0 {
        inject_mouse_move(x, y, None);
    }

    // Use SendInput instead of the deprecated mouse_event wrapper: mouse_event
    // was silently dropping button events when called from the helper service's
    // spawned injection thread on some desktops, which produced the "cursor
    // moves but cannot click" symptom. SendInput reports failures via its
    // return value and is the recommended injection API.
    //
    // The side buttons ride MOUSEEVENTF_X* with the button in mouseData
    // (XBUTTON1 = back, XBUTTON2 = forward).
    let (flag, mouse_data) = match (button, down) {
        (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
        (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
        (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
        (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
        (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
        (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
        (MouseButton::Back, true) => (MOUSEEVENTF_XDOWN, XBUTTON1 as i32),
        (MouseButton::Back, false) => (MOUSEEVENTF_XUP, XBUTTON1 as i32),
        (MouseButton::Forward, true) => (MOUSEEVENTF_XDOWN, XBUTTON2 as i32),
        (MouseButton::Forward, false) => (MOUSEEVENTF_XUP, XBUTTON2 as i32),
    };

    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: 0,
                dy: 0,
                mouseData: mouse_data as u32,
                dwFlags: flag,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    unsafe {
        if SendInput(1, &input, std::mem::size_of::<INPUT>() as i32) == 0 {
            note_injection_refused("mouse button", windows_sys::Win32::Foundation::GetLastError());
        }
    }
}

pub fn inject_scroll(delta_x: i32, delta_y: i32) {
    inject_wheel_units(delta_x.saturating_mul(120), delta_y.saturating_mul(120));
}

fn inject_wheel_units(delta_x: i32, delta_y: i32) {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_MOUSE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_WHEEL, MOUSEINPUT,
    };

    for (flag, delta) in [(MOUSEEVENTF_WHEEL, delta_y), (MOUSEEVENTF_HWHEEL, delta_x)] {
        if delta == 0 {
            continue;
        }

        let input = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    // Windows defines wheel data as a signed value stored in a
                    // DWORD. Values smaller than WHEEL_DELTA (120) are legal
                    // and are how high-resolution wheels preserve sub-notch
                    // movement for applications that support it.
                    mouseData: delta as u32,
                    dwFlags: flag,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        unsafe {
            let _ = SendInput(1, &input, std::mem::size_of::<INPUT>() as i32);
        }
    }
}

#[derive(Default)]
struct PreciseScrollRemainder {
    x: f64,
    y: f64,
}

// Conversion only; deltas remain fractional and are never snapped to 120.
// Keep this in one place so physical testing can tune speed without touching
// the protocol or macOS capture path.
const WINDOWS_WHEEL_UNITS_PER_MAC_SCROLL_UNIT: f64 = 10.0;

pub fn inject_precise_scroll(
    delta_x: f64,
    delta_y: f64,
    phase: GesturePhase,
    momentum_phase: GesturePhase,
) {
    static REMAINDER: OnceLock<Mutex<PreciseScrollRemainder>> = OnceLock::new();
    let Ok(mut remainder) = REMAINDER
        .get_or_init(|| Mutex::new(PreciseScrollRemainder::default()))
        .lock()
    else {
        return;
    };

    remainder.x += delta_x * WINDOWS_WHEEL_UNITS_PER_MAC_SCROLL_UNIT;
    remainder.y += delta_y * WINDOWS_WHEEL_UNITS_PER_MAC_SCROLL_UNIT;
    let x = remainder.x.trunc() as i32;
    let y = remainder.y.trunc() as i32;
    remainder.x -= f64::from(x);
    remainder.y -= f64::from(y);
    inject_wheel_units(x, y);

    if matches!(phase, GesturePhase::Cancelled) || matches!(momentum_phase, GesturePhase::Cancelled)
    {
        *remainder = PreciseScrollRemainder::default();
    }
}

// Change this one constant if macOS natural-scroll direction should select the
// opposite Windows virtual desktop. Vertical mappings remain unchanged.
const REVERSE_HORIZONTAL_SWIPE: bool = false;
const SWIPE_TRIGGER_DELTA: f64 = 0.35;

#[derive(Default)]
struct SwipeState {
    x: f64,
    y: f64,
    triggered: bool,
}

pub fn inject_swipe(delta_x: f64, delta_y: f64, phase: GesturePhase) {
    static STATE: OnceLock<Mutex<SwipeState>> = OnceLock::new();
    let Ok(mut state) = STATE
        .get_or_init(|| Mutex::new(SwipeState::default()))
        .lock()
    else {
        return;
    };
    if matches!(phase, GesturePhase::Began) {
        *state = SwipeState::default();
    }
    state.x += delta_x;
    state.y += delta_y;

    let ended = matches!(phase, GesturePhase::Ended | GesturePhase::Cancelled);
    let over_threshold = state.x.abs().max(state.y.abs()) >= SWIPE_TRIGGER_DELTA;
    if !state.triggered && (over_threshold || ended) {
        if state.y.abs() > state.x.abs() {
            if state.y > 0.0 {
                inject_key_chord(&[0x5B, 0x09]); // Win + Tab
            }
            // Down-swipe is intentionally reserved for a future configurable action.
        } else if state.x.abs() > f64::EPSILON {
            let points_left = state.x < 0.0;
            let windows_left = points_left ^ REVERSE_HORIZONTAL_SWIPE;
            inject_key_chord(&[0x5B, 0x11, if windows_left { 0x25 } else { 0x27 }]);
        }
        state.triggered = true;
    }
    if ended {
        *state = SwipeState::default();
    }
}

fn inject_key_chord(keys: &[u16]) {
    for key in keys {
        inject_key(*key, true);
    }
    for key in keys.iter().rev() {
        inject_key(*key, false);
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PointerInfo {
    pointer_type: u32,
    pointer_id: u32,
    frame_id: u32,
    pointer_flags: u32,
    source_device: windows_sys::Win32::Foundation::HANDLE,
    hwnd_target: windows_sys::Win32::Foundation::HWND,
    pixel_location: windows_sys::Win32::Foundation::POINT,
    himetric_location: windows_sys::Win32::Foundation::POINT,
    pixel_location_raw: windows_sys::Win32::Foundation::POINT,
    himetric_location_raw: windows_sys::Win32::Foundation::POINT,
    time: u32,
    history_count: u32,
    input_data: i32,
    key_states: u32,
    performance_count: u64,
    button_change_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PointerTouchInfo {
    pointer_info: PointerInfo,
    touch_flags: u32,
    touch_mask: u32,
    contact: windows_sys::Win32::Foundation::RECT,
    contact_raw: windows_sys::Win32::Foundation::RECT,
    orientation: u32,
    pressure: u32,
}

#[link(name = "user32")]
extern "system" {
    fn InitializeTouchInjection(max_count: u32, feedback_mode: u32) -> i32;
    fn InjectTouchInput(count: u32, contacts: *const PointerTouchInfo) -> i32;
}

const POINTER_INPUT_TYPE_TOUCH: u32 = 2;
const POINTER_FLAG_INRANGE: u32 = 0x0000_0002;
const POINTER_FLAG_INCONTACT: u32 = 0x0000_0004;
const POINTER_FLAG_DOWN: u32 = 0x0001_0000;
const POINTER_FLAG_UPDATE: u32 = 0x0002_0000;
const POINTER_FLAG_UP: u32 = 0x0004_0000;
const TOUCH_MASK_CONTACTAREA: u32 = 0x0000_0001;
const TOUCH_MASK_ORIENTATION: u32 = 0x0000_0002;
const TOUCH_MASK_PRESSURE: u32 = 0x0000_0004;
const TOUCH_FEEDBACK_NONE: u32 = 0x0000_0003;

struct PinchState {
    initialization_attempted: bool,
    touch_available: bool,
    active: bool,
    fallback: bool,
    photoshop_fallback: bool,
    center_x: i32,
    center_y: i32,
    distance: f64,
    fallback_remainder: f64,
    last_points: [(i32, i32); 2],
}

impl Default for PinchState {
    fn default() -> Self {
        Self {
            initialization_attempted: false,
            touch_available: false,
            active: false,
            fallback: false,
            photoshop_fallback: false,
            center_x: 0,
            center_y: 0,
            distance: 80.0,
            fallback_remainder: 0.0,
            last_points: [(0, 0); 2],
        }
    }
}

pub fn inject_pinch(magnification: f64, phase: GesturePhase, x: i32, y: i32) {
    static STATE: OnceLock<Mutex<PinchState>> = OnceLock::new();
    let Ok(mut state) = STATE
        .get_or_init(|| Mutex::new(PinchState::default()))
        .lock()
    else {
        return;
    };

    if !state.active || matches!(phase, GesturePhase::Began) {
        start_pinch(&mut state, x, y);
    }

    if state.fallback {
        inject_pinch_fallback(&mut state, magnification);
    } else if state.active && !matches!(phase, GesturePhase::Began) {
        state.distance =
            (state.distance * (1.0 + magnification).clamp(0.5, 1.5)).clamp(12.0, 500.0);
        let points = pinch_points(state.center_x, state.center_y, state.distance);
        if inject_touch_frame(
            points,
            POINTER_FLAG_INRANGE | POINTER_FLAG_INCONTACT | POINTER_FLAG_UPDATE,
        ) {
            state.last_points = points;
        } else {
            finish_touch_pinch(&mut state);
            state.fallback = true;
            state.active = true;
            inject_pinch_fallback(&mut state, magnification);
        }
    }

    if matches!(phase, GesturePhase::Ended | GesturePhase::Cancelled) {
        if !state.fallback {
            finish_touch_pinch(&mut state);
        }
        state.active = false;
        state.fallback = false;
        state.photoshop_fallback = false;
        state.fallback_remainder = 0.0;
    }
}

fn start_pinch(state: &mut PinchState, x: i32, y: i32) {
    if !state.initialization_attempted {
        state.initialization_attempted = true;
        state.touch_available = unsafe { InitializeTouchInjection(2, TOUCH_FEEDBACK_NONE) } != 0;
        if !state.touch_available {
            log::info!("touch injection unavailable; pinch will use Ctrl+Wheel fallback");
        }
    }
    state.center_x = x;
    state.center_y = y;
    state.distance = 80.0;
    state.fallback_remainder = 0.0;
    state.last_points = pinch_points(x, y, state.distance);
    state.photoshop_fallback = windows_foreground_process_is_photoshop();
    if state.photoshop_fallback {
        log::info!("Photoshop foreground detected; pinch will use Ctrl+Add/Subtract fallback");
    }
    state.fallback = state.photoshop_fallback
        || !state.touch_available
        || !inject_touch_frame(
            state.last_points,
            POINTER_FLAG_INRANGE | POINTER_FLAG_INCONTACT | POINTER_FLAG_DOWN,
        );
    state.active = true;
}

fn finish_touch_pinch(state: &mut PinchState) {
    if state.touch_available {
        let _ = inject_touch_frame(state.last_points, POINTER_FLAG_INRANGE | POINTER_FLAG_UP);
    }
}

fn pinch_points(center_x: i32, center_y: i32, distance: f64) -> [(i32, i32); 2] {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };

    let half = (distance / 2.0).round() as i32;
    let (left, top, right, bottom) = unsafe {
        let left = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let top = GetSystemMetrics(SM_YVIRTUALSCREEN);
        (
            left,
            top,
            left + GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1) - 1,
            top + GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1) - 1,
        )
    };
    let contact_left = (left + 2).min(right);
    let contact_right = (right - 2).max(contact_left);
    let contact_top = (top + 2).min(bottom);
    let contact_bottom = (bottom - 2).max(contact_top);
    [
        (
            (center_x - half).clamp(contact_left, contact_right),
            center_y.clamp(contact_top, contact_bottom),
        ),
        (
            (center_x + half).clamp(contact_left, contact_right),
            center_y.clamp(contact_top, contact_bottom),
        ),
    ]
}

fn inject_touch_frame(points: [(i32, i32); 2], flags: u32) -> bool {
    let contacts = [
        touch_contact(1, points[0].0, points[0].1, flags),
        touch_contact(2, points[1].0, points[1].1, flags),
    ];
    unsafe { InjectTouchInput(contacts.len() as u32, contacts.as_ptr()) != 0 }
}

fn touch_contact(pointer_id: u32, x: i32, y: i32, flags: u32) -> PointerTouchInfo {
    use windows_sys::Win32::Foundation::{POINT, RECT};

    let point = POINT { x, y };
    let contact = RECT {
        left: x - 2,
        top: y - 2,
        right: x + 2,
        bottom: y + 2,
    };
    PointerTouchInfo {
        pointer_info: PointerInfo {
            pointer_type: POINTER_INPUT_TYPE_TOUCH,
            pointer_id,
            frame_id: 0,
            pointer_flags: flags,
            source_device: std::ptr::null_mut(),
            hwnd_target: std::ptr::null_mut(),
            pixel_location: point,
            himetric_location: POINT { x: 0, y: 0 },
            pixel_location_raw: point,
            himetric_location_raw: POINT { x: 0, y: 0 },
            time: 0,
            history_count: 0,
            input_data: 0,
            key_states: 0,
            performance_count: 0,
            button_change_type: 0,
        },
        touch_flags: 0,
        touch_mask: TOUCH_MASK_CONTACTAREA | TOUCH_MASK_ORIENTATION | TOUCH_MASK_PRESSURE,
        contact,
        contact_raw: contact,
        orientation: 90,
        pressure: 32_000,
    }
}

fn inject_pinch_fallback(state: &mut PinchState, magnification: f64) {
    if state.photoshop_fallback {
        const PHOTOSHOP_ZOOM_STEP: f64 = 0.04;
        state.fallback_remainder += magnification;
        while state.fallback_remainder.abs() >= PHOTOSHOP_ZOOM_STEP {
            let zoom_in = state.fallback_remainder > 0.0;
            inject_key_chord(&[0x11, if zoom_in { 0x6B } else { 0x6D }]);
            state.fallback_remainder -= if zoom_in {
                PHOTOSHOP_ZOOM_STEP
            } else {
                -PHOTOSHOP_ZOOM_STEP
            };
        }
        return;
    }
    state.fallback_remainder += magnification * 1200.0;
    let delta = state.fallback_remainder.trunc() as i32;
    state.fallback_remainder -= f64::from(delta);
    if delta != 0 {
        inject_key(0x11, true); // Ctrl
        inject_wheel_units(0, delta);
        inject_key(0x11, false);
    }
}

fn windows_foreground_process_is_photoshop() -> bool {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, MAX_PATH},
        System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        },
        UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId},
    };

    let window = unsafe { GetForegroundWindow() };
    if window.is_null() {
        return false;
    }
    let mut process_id = 0_u32;
    unsafe { GetWindowThreadProcessId(window, &mut process_id) };
    if process_id == 0 {
        return false;
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return false;
    }
    let mut path = [0_u16; MAX_PATH as usize];
    let mut length = path.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut length) } != 0;
    unsafe {
        CloseHandle(process);
    }
    ok && String::from_utf16_lossy(&path[..length as usize])
        .rsplit(['\\', '/'])
        .next()
        .is_some_and(|name| name.to_ascii_lowercase().contains("photoshop"))
}

pub fn inject_key(key_code: u16, down: bool) {
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        MapVirtualKeyW, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT,
        KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, MAPVK_VK_TO_VSC,
    };

    let mut dw_flags = if down { 0 } else { KEYEVENTF_KEYUP };
    if is_extended_key_vk(key_code) {
        dw_flags |= KEYEVENTF_EXTENDEDKEY;
    }

    let scan = unsafe { MapVirtualKeyW(key_code as u32, MAPVK_VK_TO_VSC) } as u16;

    // Use SendInput instead of keybd_event: same reason as inject_mouse_button
    // — keybd_event was silently dropping key events from the helper's spawned
    // thread, leaving the keyboard dead while mouse moves still worked.
    let input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: key_code,
                wScan: scan,
                dwFlags: dw_flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    unsafe {
        if SendInput(1, &input, std::mem::size_of::<INPUT>() as i32) == 0 {
            note_injection_refused("key", windows_sys::Win32::Foundation::GetLastError());
        }
    }
}

fn is_extended_key_vk(vk: u16) -> bool {
    matches!(
        vk,
        0x21 | 0x22
            | 0x23
            | 0x24
            | 0x25
            | 0x26
            | 0x27
            | 0x28
            | 0x2C
            | 0x2D
            | 0x2E
            | 0x5B
            | 0x5C
            | 0x5D
            | 0x6F
            | 0x90
            | 0xA3
            | 0xA5
    )
}

pub fn send_secure_attention() -> Result<(), String> {
    use windows_sys::Win32::{
        Foundation::FreeLibrary,
        System::LibraryLoader::{GetProcAddress, LoadLibraryW},
    };

    type SendSasFn = unsafe extern "system" fn(windows_sys::core::BOOL);

    unsafe {
        let dll = LoadLibraryW(crate::wide_null("sas.dll").as_ptr());
        if dll.is_null() {
            return Err("SAS.dll is not available on this Windows installation".into());
        }
        let Some(proc) = GetProcAddress(dll, c"SendSAS".as_ptr() as *const u8) else {
            let _ = FreeLibrary(dll);
            return Err("SendSAS entry point is not available".into());
        };
        let send_sas: SendSasFn = std::mem::transmute(proc);
        send_sas(0);
        let _ = FreeLibrary(dll);
    }
    Ok(())
}
