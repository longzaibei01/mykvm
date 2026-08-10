use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const LEFT_BUTTON_MASK: u64 = 1;
pub const RIGHT_BUTTON_MASK: u64 = 1 << 1;
pub const MIDDLE_BUTTON_MASK: u64 = 1 << 2;
pub const BACK_BUTTON_MASK: u64 = 1 << 3;
pub const FORWARD_BUTTON_MASK: u64 = 1 << 4;
pub const INPUT_PIPE_PREFIX: &str = r"\\.\pipe\mykvm-input-s";
pub const INPUT_SERVICE_NAME: &str = "MyKVMInputService";
pub const INPUT_SERVICE_DISPLAY_NAME: &str = "MyKVM Lock Screen Input Service";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum InputEvent {
    MouseMove {
        screen_id: String,
        x: i32,
        y: i32,
    },
    MouseButton {
        button: MouseButton,
        down: bool,
    },
    Scroll {
        delta_x: i32,
        delta_y: i32,
    },
    PreciseScroll {
        delta_x: f64,
        delta_y: f64,
        phase: GesturePhase,
        momentum_phase: GesturePhase,
    },
    Swipe {
        delta_x: f64,
        delta_y: f64,
        phase: GesturePhase,
    },
    Pinch {
        magnification: f64,
        phase: GesturePhase,
    },
    GestureAction {
        action: GestureAction,
    },
    Key {
        key_code: u16,
        down: bool,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GesturePhase {
    None,
    Began,
    Changed,
    Ended,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GestureAction {
    TaskView,
    ShowDesktop,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    // The side navigation buttons (Windows XBUTTON1/XBUTTON2, "back"/"forward").
    Back,
    Forward,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum InputCommand {
    MouseMove {
        x: i32,
        y: i32,
        drag_button: Option<MouseButton>,
    },
    MouseButton {
        button: MouseButton,
        down: bool,
        x: i32,
        y: i32,
    },
    Scroll {
        delta_x: i32,
        delta_y: i32,
    },
    PreciseScroll {
        delta_x: f64,
        delta_y: f64,
        phase: GesturePhase,
        momentum_phase: GesturePhase,
    },
    Swipe {
        delta_x: f64,
        delta_y: f64,
        phase: GesturePhase,
    },
    Pinch {
        magnification: f64,
        phase: GesturePhase,
        x: i32,
        y: i32,
    },
    GestureAction {
        action: GestureAction,
    },
    Key {
        key_code: u16,
        down: bool,
    },
    ReleaseAll,
    SecureAttention,
}

pub fn input_pipe_name(session_id: u32) -> String {
    format!("{INPUT_PIPE_PREFIX}{session_id}")
}

pub fn input_helper_status_path(session_id: u32) -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("MyKVM")
        .join(format!("input-helper-status-s{session_id}.txt"))
}

pub fn mouse_button_mask(button: MouseButton) -> u64 {
    match button {
        MouseButton::Left => LEFT_BUTTON_MASK,
        MouseButton::Right => RIGHT_BUTTON_MASK,
        MouseButton::Middle => MIDDLE_BUTTON_MASK,
        MouseButton::Back => BACK_BUTTON_MASK,
        MouseButton::Forward => FORWARD_BUTTON_MASK,
    }
}

pub fn button_from_mask(mask: u64) -> Option<MouseButton> {
    if mask & LEFT_BUTTON_MASK != 0 {
        Some(MouseButton::Left)
    } else if mask & RIGHT_BUTTON_MASK != 0 {
        Some(MouseButton::Right)
    } else if mask & MIDDLE_BUTTON_MASK != 0 {
        Some(MouseButton::Middle)
    } else {
        None
    }
}

pub fn encode_input_command(command: &InputCommand) -> Result<Vec<u8>, String> {
    let payload = rmp_serde::to_vec_named(command)
        .map_err(|error| format!("encode input command: {error}"))?;
    if payload.len() > u32::MAX as usize {
        return Err("input command is too large".into());
    }

    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    framed.extend_from_slice(&payload);
    Ok(framed)
}

pub fn decode_input_command(payload: &[u8]) -> Result<InputCommand, String> {
    rmp_serde::from_slice::<InputCommand>(payload)
        .map_err(|error| format!("decode input command: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_command_frame_round_trips() {
        let command = InputCommand::MouseButton {
            button: MouseButton::Left,
            down: true,
            x: 320,
            y: 240,
        };

        let framed = encode_input_command(&command).expect("encode input command");
        let payload_len = u32::from_le_bytes(
            framed[0..4]
                .try_into()
                .expect("length prefix should be four bytes"),
        ) as usize;

        assert_eq!(payload_len, framed.len() - 4);
        assert_eq!(
            decode_input_command(&framed[4..]).expect("decode input command"),
            command
        );
    }

    #[test]
    fn trackpad_commands_round_trip() {
        let commands = [
            InputCommand::PreciseScroll {
                delta_x: 0.375,
                delta_y: -1.625,
                phase: GesturePhase::Changed,
                momentum_phase: GesturePhase::Began,
            },
            InputCommand::Swipe {
                delta_x: -0.75,
                delta_y: 0.0,
                phase: GesturePhase::Ended,
            },
            InputCommand::Pinch {
                magnification: 0.125,
                phase: GesturePhase::Changed,
                x: 640,
                y: 480,
            },
            InputCommand::GestureAction {
                action: GestureAction::TaskView,
            },
        ];

        for command in commands {
            let framed = encode_input_command(&command).expect("encode trackpad command");
            let decoded = decode_input_command(&framed[4..]).expect("decode trackpad command");
            assert_eq!(decoded, command);
        }
    }
}
