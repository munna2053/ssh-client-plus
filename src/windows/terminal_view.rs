use super::{
    crypto::Secret,
    theme::{self, Object},
    wide,
};
use crate::{Result, terminal::Terminal};
use std::{
    cell::RefCell,
    ptr::{null, null_mut},
    sync::mpsc::SyncSender,
};
use windows_sys::Win32::{
    Foundation::{GlobalFree, HWND, LPARAM, LRESULT, RECT, WPARAM},
    Graphics::Gdi::*,
    System::{DataExchange::*, LibraryLoader::GetModuleHandleW, Memory::*},
    UI::{HiDpi::GetDpiForWindow, Input::KeyboardAndMouse::*, WindowsAndMessaging::*},
};

pub const RESIZED: u32 = WM_APP + 201;
pub const ACTIVITY: u32 = WM_APP + 202;
const CF_UNICODETEXT: u32 = 13;
const PADDING: i32 = 14;

struct View {
    model: Terminal,
    input: Option<SyncSender<Secret>>,
    font: Object,
    bold: Object,
    heading: Object,
    body: Object,
    dpi: u32,
    width: i32,
    height: i32,
    scroll: usize,
    selection: Option<((usize, usize), (usize, usize))>,
    selecting: bool,
    surrogate: Option<u16>,
    suppress: Option<u32>,
    has_output: bool,
}

fn cell(window: HWND) -> Option<&'static RefCell<View>> {
    // SAFETY: window user data is zero or our Box<RefCell<View>> until WM_NCDESTROY.
    let pointer = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *const RefCell<View>;
    if pointer.is_null() {
        None
    } else {
        // SAFETY: caller uses the reference only within the current synchronous window operation.
        Some(unsafe { &*pointer })
    }
}

impl View {
    fn fonts(dpi: u32) -> Result<(Object, Object, Object, Object)> {
        Ok((
            theme::font("Consolas", 17, dpi, false)?,
            theme::font("Consolas", 17, dpi, true)?,
            theme::font("Segoe UI", 23, dpi, true)?,
            theme::font("Segoe UI", 15, dpi, false)?,
        ))
    }
    fn measure(&mut self, window: HWND) {
        // SAFETY: live window's DC is acquired/released in this block; borrowed font is restored before release.
        unsafe {
            let dc = GetDC(window);
            if dc.is_null() {
                return;
            }
            let old = SelectObject(dc, self.font.0);
            let mut metrics = TEXTMETRICW::default();
            GetTextMetricsW(dc, &mut metrics);
            self.width = metrics.tmAveCharWidth.max(6);
            self.height = metrics.tmHeight.max(12) + theme::scale(3, self.dpi);
            SelectObject(dc, old);
            ReleaseDC(window, dc);
        }
    }
    fn layout(&mut self, window: HWND) {
        // SAFETY: queries current DPI for the live child window.
        let dpi = unsafe { GetDpiForWindow(window) }.max(96);
        if dpi != self.dpi
            && let Ok((font, bold, heading, body)) = Self::fonts(dpi)
        {
            self.font = font;
            self.bold = bold;
            self.heading = heading;
            self.body = body;
            self.dpi = dpi;
            self.measure(window);
        }
        let mut rect = RECT::default();
        // SAFETY: output rectangle is valid and the child handle is live.
        unsafe {
            GetClientRect(window, &mut rect);
        }
        let pad = theme::scale(PADDING, self.dpi);
        let columns = ((rect.right - pad * 2) / self.width).max(2) as usize;
        let rows = ((rect.bottom - pad * 2) / self.height).max(2) as usize;
        if (
            columns.min(crate::terminal::MAX_COLUMNS),
            rows.min(crate::terminal::MAX_ROWS),
        ) != (self.model.columns, self.model.rows)
        {
            self.model.resize(columns, rows);
            self.selection = None;
            // SAFETY: posts a signal with no pointers; the parent queries this view's bounded dimensions.
            unsafe {
                PostMessageW(GetParent(window), RESIZED, window as WPARAM, 0);
            }
        }
    }
    fn send(&mut self, window: HWND, bytes: Vec<u8>) {
        if let Some(input) = &self.input {
            // Bounded nonblocking queue keeps an unresponsive remote host from blocking the UI.
            for chunk in bytes.chunks(2048) {
                if input.try_send(Secret(chunk.to_vec())).is_err() {
                    break;
                }
            }
            self.input_sent(window);
        }
        // Clear this owned staging buffer as well as packets cleared by the writer.
        drop(Secret(bytes));
    }
    fn input_sent(&mut self, window: HWND) {
        self.scroll = 0;
        self.selection = None;
        // SAFETY: activity carries no pointer or secret and does not synchronously reenter the parent.
        unsafe {
            PostMessageW(GetParent(window), ACTIVITY, 0, 0);
            InvalidateRect(window, null(), 0);
        }
    }
    fn point(&self, parameter: LPARAM) -> (usize, usize) {
        let pad = theme::scale(PADDING, self.dpi);
        let x = (parameter as u16 as i16 as i32 - pad).max(0) / self.width;
        let y = ((parameter >> 16) as u16 as i16 as i32 - pad).max(0) / self.height;
        (
            (y as usize).min(self.model.rows - 1),
            (x as usize).min(self.model.columns - 1),
        )
    }
    fn selected(&self, row: usize, column: usize) -> bool {
        self.selection.is_some_and(|(a, b)| {
            let (start, end) = if a <= b { (a, b) } else { (b, a) };
            (row, column) >= start && (row, column) <= end
        })
    }
    fn paint(&self, window: HWND) {
        // SAFETY: paint DC is borrowed only within the paired BeginPaint/EndPaint operation.
        unsafe {
            let mut paint = PAINTSTRUCT::default();
            let dc = BeginPaint(window, &mut paint);
            self.render(window, dc);
            EndPaint(window, &paint);
        }
    }

    fn render(&self, window: HWND, output: HDC) {
        // SAFETY: the callback supplies a live DC; all temporary GDI selections are restored before release.
        unsafe {
            let mut bounds = RECT::default();
            GetClientRect(window, &mut bounds);
            let dc = CreateCompatibleDC(output);
            let bitmap = CreateCompatibleBitmap(output, bounds.right.max(1), bounds.bottom.max(1));
            if dc.is_null() || bitmap.is_null() {
                if !dc.is_null() {
                    DeleteDC(dc);
                }
                if !bitmap.is_null() {
                    DeleteObject(bitmap);
                }
                return;
            }
            let old_bitmap = SelectObject(dc, bitmap);
            let old_font = SelectObject(dc, self.font.0);
            SetDCBrushColor(dc, theme::color(theme::CANVAS));
            FillRect(dc, &bounds, GetStockObject(DC_BRUSH));
            let pad = theme::scale(PADDING, self.dpi);
            if !self.has_output {
                let middle = bounds.bottom / 2 - theme::scale(50, self.dpi);
                theme::text(
                    dc,
                    RECT {
                        left: pad,
                        top: middle,
                        right: bounds.right - pad,
                        bottom: middle + theme::scale(40, self.dpi),
                    },
                    "Your terminal lives here",
                    self.heading.0,
                    theme::TEXT,
                    DT_CENTER | DT_SINGLELINE | DT_VCENTER,
                );
                theme::text(
                    dc,
                    RECT {
                        left: pad,
                        top: middle + theme::scale(46, self.dpi),
                        right: bounds.right - pad,
                        bottom: middle + theme::scale(84, self.dpi),
                    },
                    "Open Servers to connect or add your first server.",
                    self.body.0,
                    theme::MUTED,
                    DT_CENTER | DT_SINGLELINE | DT_VCENTER,
                );
            } else {
                for row in 0..self.model.rows {
                    for column in 0..self.model.columns {
                        let Some(cell) = self.model.cell(row, column, self.scroll) else {
                            continue;
                        };
                        if cell.continuation {
                            continue;
                        }
                        let wide_cell = self
                            .model
                            .cell(row, column + 1, self.scroll)
                            .is_some_and(|cell| cell.continuation);
                        let rect = RECT {
                            left: pad + column as i32 * self.width,
                            top: pad + row as i32 * self.height,
                            right: pad
                                + (column + if wide_cell { 2 } else { 1 }) as i32 * self.width,
                            bottom: pad + (row + 1) as i32 * self.height,
                        };
                        let (mut foreground, mut background) = if cell.style.inverse {
                            (cell.style.background, cell.style.foreground)
                        } else {
                            (cell.style.foreground, cell.style.background)
                        };
                        if self.selected(row, column) {
                            foreground = theme::TEXT;
                            background = theme::SELECTED;
                        }
                        SetTextColor(dc, theme::color(foreground));
                        SetBkColor(dc, theme::color(background));
                        SelectObject(
                            dc,
                            if cell.style.bold {
                                self.bold.0
                            } else {
                                self.font.0
                            },
                        );
                        let text = wide(cell.glyph());
                        ExtTextOutW(
                            dc,
                            rect.left,
                            rect.top,
                            ETO_CLIPPED | ETO_OPAQUE,
                            &rect,
                            text.as_ptr(),
                            (text.len() - 1) as u32,
                            null(),
                        );
                        if cell.style.underline {
                            let underline = RECT {
                                top: rect.bottom - 3,
                                bottom: rect.bottom - 2,
                                ..rect
                            };
                            SetDCBrushColor(dc, theme::color(foreground));
                            FillRect(dc, &underline, GetStockObject(DC_BRUSH));
                        }
                    }
                }
                if self.scroll == 0
                    && self.model.cursor_visible
                    && self.input.is_some()
                    && GetFocus() == window
                {
                    let (row, column) = self.model.cursor();
                    let rect = RECT {
                        left: pad + column as i32 * self.width,
                        top: pad + (row + 1) as i32 * self.height - 3,
                        right: pad + (column + 1) as i32 * self.width,
                        bottom: pad + (row + 1) as i32 * self.height - 1,
                    };
                    SetDCBrushColor(dc, theme::color(theme::GREEN));
                    FillRect(dc, &rect, GetStockObject(DC_BRUSH));
                }
            }
            BitBlt(output, 0, 0, bounds.right, bounds.bottom, dc, 0, 0, SRCCOPY);
            SelectObject(dc, old_font);
            SelectObject(dc, old_bitmap);
            DeleteObject(bitmap);
            DeleteDC(dc);
        }
    }
    fn paste(&mut self, window: HWND) {
        let Ok(text) = clipboard_text(window) else {
            return;
        };
        let packet = paste_packet(text, self.model.bracketed_paste);
        // One packet is queued whole or not at all, so backpressure cannot drop a closing delimiter.
        if let Some(input) = &self.input
            && input.try_send(packet).is_ok()
        {
            self.input_sent(window);
        }
    }
    fn copy(&self, window: HWND) {
        if let Some((start, end)) = self.selection {
            let text = self.model.selection(start, end, self.scroll);
            let _ = set_clipboard_text(window, &text);
        }
    }
}

pub(crate) fn create(parent: HWND, id: usize) -> Result<HWND> {
    let class = wide("SentinelSSH.Terminal.v1");
    // SAFETY: class and module pointers remain valid; the child belongs to this parent.
    let window = unsafe {
        let module = GetModuleHandleW(null());
        let definition = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: module,
            lpszClassName: class.as_ptr(),
            hCursor: LoadCursorW(null_mut(), IDC_IBEAM),
            ..Default::default()
        };
        RegisterClassW(&definition);
        CreateWindowExW(
            0,
            class.as_ptr(),
            wide("").as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            0,
            0,
            800,
            500,
            parent,
            id as *mut _,
            module,
            null(),
        )
    };
    if window.is_null() {
        return Err("Cannot create the embedded terminal view.".into());
    }
    // SAFETY: parent is a live window and DPI query needs no owned resource.
    let dpi = unsafe { GetDpiForWindow(parent) }.max(96);
    let (font, bold, heading, body) = View::fonts(dpi)?;
    let mut view = View {
        model: Terminal::new(80, 24),
        input: None,
        font,
        bold,
        heading,
        body,
        dpi,
        width: 9,
        height: 22,
        scroll: 0,
        selection: None,
        selecting: false,
        surrogate: None,
        suppress: None,
        has_output: false,
    };
    view.measure(window);
    view.layout(window);
    let pointer = Box::into_raw(Box::new(RefCell::new(view)));
    // SAFETY: ownership is attached once and released in WM_NCDESTROY.
    unsafe {
        SetWindowLongPtrW(window, GWLP_USERDATA, pointer as isize);
    }
    Ok(window)
}

pub(crate) fn size(window: HWND) -> (usize, usize) {
    cell(window)
        .and_then(|cell| {
            cell.try_borrow()
                .ok()
                .map(|view| (view.model.columns, view.model.rows))
        })
        .unwrap_or((80, 24))
}

#[cfg(test)]
pub(crate) fn snapshot(window: HWND) -> String {
    let view = cell(window).unwrap().borrow();
    view.model
        .selection((0, 0), (view.model.rows - 1, view.model.columns - 1), 0)
}

pub(crate) fn attach(window: HWND, input: Option<SyncSender<Secret>>, reset: bool) {
    if let Some(cell) = cell(window)
        && let Ok(mut view) = cell.try_borrow_mut()
    {
        view.input = input;
        if reset {
            view.model.reset();
            view.has_output = false;
            view.scroll = 0;
            view.selection = None;
        }
    }
    // SAFETY: invalidation is asynchronous and retains no pointer.
    unsafe {
        InvalidateRect(window, null(), 0);
    }
}

pub(crate) fn insert_command(window: HWND, command: &str) -> Result<()> {
    if command.is_empty() || command.len() > 2048 || command.chars().any(char::is_control) {
        return Err("Command shortcuts require a single line without control characters.".into());
    }
    let cell = cell(window).ok_or("The terminal is unavailable.")?;
    let mut view = cell
        .try_borrow_mut()
        .map_err(|_| "The terminal is busy. Try again.")?;
    let input = view
        .input
        .as_ref()
        .ok_or("Connect to a server before using command shortcuts.")?;
    let bytes = if view.model.bracketed_paste {
        format!("\x1b[200~{command}\x1b[201~").into_bytes()
    } else {
        command.as_bytes().to_vec()
    };
    input
        .try_send(Secret(bytes))
        .map_err(|_| "The terminal cannot accept input right now. Try again.")?;
    view.scroll = 0;
    view.selection = None;
    // SAFETY: these asynchronous messages carry no pointers and target this live terminal and parent.
    unsafe {
        PostMessageW(GetParent(window), ACTIVITY, 0, 0);
        InvalidateRect(window, null(), 0);
    }
    Ok(())
}

pub(crate) fn feed(window: HWND, bytes: &[u8]) {
    update(window, bytes, None);
}

pub(crate) fn feed_session(window: HWND, bytes: &[u8], protocol_input: &SyncSender<Secret>) {
    update(window, bytes, Some(protocol_input));
}

fn update(window: HWND, bytes: &[u8], protocol_input: Option<&SyncSender<Secret>>) {
    if let Some(cell) = cell(window)
        && let Ok(mut view) = cell.try_borrow_mut()
    {
        let history = view.model.history_len();
        let reply = view.model.feed(bytes);
        if view.scroll != 0 {
            view.scroll = (view.scroll + view.model.history_len().saturating_sub(history))
                .min(view.model.history_len());
        }
        view.has_output = true;
        view.selection = None;
        if !reply.is_empty()
            && let Some(input) = protocol_input.or(view.input.as_ref())
        {
            let _ = input.try_send(Secret(reply));
        }
    }
    // SAFETY: output is rendered on the UI thread during the next paint.
    unsafe {
        InvalidateRect(window, null(), 0);
    }
}

fn key_bytes(
    key: u16,
    shift: bool,
    alt: bool,
    control: bool,
    application: bool,
) -> Option<Vec<u8>> {
    let modifier = 1 + usize::from(shift) + 2 * usize::from(alt) + 4 * usize::from(control);
    let final_byte = match key {
        VK_UP => Some('A'),
        VK_DOWN => Some('B'),
        VK_RIGHT => Some('C'),
        VK_LEFT => Some('D'),
        VK_HOME => Some('H'),
        VK_END => Some('F'),
        VK_F1 => Some('P'),
        VK_F2 => Some('Q'),
        VK_F3 => Some('R'),
        VK_F4 => Some('S'),
        _ => None,
    };
    if let Some(letter) = final_byte {
        return Some(
            if modifier != 1 {
                format!("\x1b[1;{modifier}{letter}")
            } else if application || (VK_F1..=VK_F4).contains(&key) {
                format!("\x1bO{letter}")
            } else {
                format!("\x1b[{letter}")
            }
            .into_bytes(),
        );
    }
    let number = match key {
        VK_INSERT => 2,
        VK_DELETE => 3,
        VK_PRIOR => 5,
        VK_NEXT => 6,
        VK_F5 => 15,
        VK_F6 => 17,
        VK_F7 => 18,
        VK_F8 => 19,
        VK_F9 => 20,
        VK_F10 => 21,
        VK_F11 => 23,
        VK_F12 => 24,
        _ => return None,
    };
    Some(
        if modifier == 1 {
            format!("\x1b[{number}~")
        } else {
            format!("\x1b[{number};{modifier}~")
        }
        .into_bytes(),
    )
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCDESTROY {
        // SAFETY: clear window ownership before dropping the exclusively owned box.
        unsafe {
            let pointer = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut RefCell<View>;
            SetWindowLongPtrW(window, GWLP_USERDATA, 0);
            if !pointer.is_null() {
                drop(Box::from_raw(pointer));
            }
        }
    } else if let Some(cell) = cell(window)
        && let Ok(mut view) = cell.try_borrow_mut()
    {
        if matches!(
            message,
            WM_KEYDOWN | WM_SYSKEYDOWN | WM_CHAR | WM_SYSCHAR | WM_LBUTTONDOWN | WM_MOUSEWHEEL
        ) || (message == WM_MOUSEMOVE && view.selecting)
        {
            // SAFETY: only user interaction resets the parent's idle timer; output/query replies do not.
            unsafe {
                PostMessageW(GetParent(window), ACTIVITY, 0, 0);
            }
        }
        match message {
            WM_ERASEBKGND => return 1,
            WM_GETDLGCODE => return (DLGC_WANTALLKEYS | DLGC_WANTCHARS | DLGC_WANTARROWS) as isize,
            WM_PAINT => {
                view.paint(window);
                return 0;
            }
            WM_PRINTCLIENT => {
                view.render(window, wparam as HDC);
                return 0;
            }
            WM_SIZE => {
                view.layout(window);
                return 0;
            }
            WM_SETFOCUS | WM_KILLFOCUS => {
                // SAFETY: schedules repaint of focus cursor only.
                unsafe {
                    InvalidateRect(window, null(), 0);
                }
                return 0;
            }
            WM_LBUTTONDOWN => {
                let position = view.point(lparam);
                view.selection = Some((position, position));
                view.selecting = true;
                // SAFETY: capture/focus belong to this live child.
                unsafe {
                    SetCapture(window);
                    SetFocus(window);
                    InvalidateRect(window, null(), 0);
                }
                return 0;
            }
            WM_MOUSEMOVE if view.selecting => {
                let position = view.point(lparam);
                if let Some((start, _)) = view.selection {
                    view.selection = Some((start, position));
                }
                // SAFETY: schedules repaint for the updated selection.
                unsafe {
                    InvalidateRect(window, null(), 0);
                }
                return 0;
            }
            WM_LBUTTONUP => {
                view.selecting = false;
                // SAFETY: releases this thread's mouse capture.
                unsafe {
                    ReleaseCapture();
                }
                return 0;
            }
            WM_MOUSEWHEEL => {
                let delta = (wparam >> 16) as u16 as i16 as i32;
                if delta > 0 {
                    view.scroll = (view.scroll + 3).min(view.model.history_len());
                } else {
                    view.scroll = view.scroll.saturating_sub(3);
                }
                view.selection = None;
                // SAFETY: schedules scrollback repaint.
                unsafe {
                    InvalidateRect(window, null(), 0);
                }
                return 0;
            }
            WM_KEYDOWN | WM_SYSKEYDOWN => {
                // SAFETY: reads modifier state, without modifying global keyboard state.
                let (shift, alt, control) = unsafe {
                    (
                        GetKeyState(VK_SHIFT as i32) < 0,
                        GetKeyState(VK_MENU as i32) < 0,
                        GetKeyState(VK_CONTROL as i32) < 0,
                    )
                };
                let key = wparam as u16;
                if key == VK_F4 && alt {
                }
                // Let the standard Alt+F4 close command reach the parent.
                else if control && key == b'V' as u16 {
                    view.paste(window);
                    view.suppress = Some(22);
                    return 0;
                } else if control && key == b'C' as u16 && (shift || view.selection.is_some()) {
                    view.copy(window);
                    view.suppress = Some(3);
                    return 0;
                } else if shift && matches!(key, VK_PRIOR | VK_NEXT) {
                    if key == VK_PRIOR {
                        view.scroll = (view.scroll + view.model.rows).min(view.model.history_len());
                    } else {
                        view.scroll = view.scroll.saturating_sub(view.model.rows);
                    }
                    // SAFETY: schedules scrollback repaint.
                    unsafe {
                        InvalidateRect(window, null(), 0);
                    }
                    return 0;
                } else if key == VK_TAB && shift {
                    view.send(window, b"\x1b[Z".to_vec());
                    view.suppress = Some(9);
                    return 0;
                } else if let Some(bytes) =
                    key_bytes(key, shift, alt, control, view.model.application_cursor)
                {
                    view.send(window, bytes);
                    return 0;
                }
            }
            WM_CHAR | WM_SYSCHAR => {
                if view.suppress.take() == Some(wparam as u32) {
                    return 0;
                }
                let unit = wparam as u16;
                if (0xd800..=0xdbff).contains(&unit) {
                    view.surrogate = Some(unit);
                    return 0;
                }
                let character = if let Some(high) = view.surrogate.take() {
                    char::decode_utf16([high, unit])
                        .next()
                        .unwrap()
                        .unwrap_or('\u{fffd}')
                } else {
                    char::from_u32(unit as u32).unwrap_or('\u{fffd}')
                };
                let mut buffer = [0; 4];
                let mut bytes = character.encode_utf8(&mut buffer).as_bytes().to_vec();
                if character == '\u{8}' {
                    bytes = vec![127];
                }
                if message == WM_SYSCHAR {
                    bytes.insert(0, 27);
                }
                view.send(window, bytes);
                return 0;
            }
            _ => {}
        }
    }
    // SAFETY: forwards unhandled native messages with unchanged arguments.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

struct Clipboard;
impl Drop for Clipboard {
    fn drop(&mut self) {
        // SAFETY: guard owns this thread's successful OpenClipboard call.
        unsafe {
            CloseClipboard();
        }
    }
}
fn clipboard_text(window: HWND) -> Result<Secret> {
    // SAFETY: opens the clipboard on the UI thread; returned guard closes it on all exits.
    if unsafe { OpenClipboard(window) } == 0 {
        return Err("Clipboard unavailable.".into());
    }
    let _guard = Clipboard;
    // SAFETY: handle remains owned by the clipboard while it is open; allocation size bounds the read.
    unsafe {
        let handle = GetClipboardData(CF_UNICODETEXT);
        if handle.is_null() {
            return Err("No text on clipboard.".into());
        }
        let count = GlobalSize(handle) / 2;
        if count == 0 || count > 32769 {
            return Err("Paste is limited to 32 KiB of text.".into());
        }
        let data = GlobalLock(handle).cast::<u16>();
        if data.is_null() {
            return Err("Cannot read clipboard.".into());
        }
        let units = std::slice::from_raw_parts(data, count);
        let length = units.iter().position(|unit| *unit == 0).unwrap_or(count);
        let text = String::from_utf16(units.get(..length).unwrap())
            .map(|text| Secret(text.into_bytes()))
            .map_err(|_| "Clipboard text is invalid.".to_string());
        GlobalUnlock(handle);
        let text = text?;
        if text.0.len() > 32768 {
            return Err("Paste is limited to 32 KiB of text.".into());
        }
        Ok(text)
    }
}
// Clipboard text may come from an attacker, so only printable text, tabs, and line breaks are sent.
// Removing every C0/C1 control keeps it from ending a bracketed paste early or forging keystrokes.
fn paste_packet(mut text: Secret, bracketed: bool) -> Secret {
    let bytes = &mut text.0;
    let mut kept = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;
        let output = match byte {
            b'\r' => {
                if bytes.get(index) == Some(&b'\n') {
                    index += 1;
                }
                Some(b'\r')
            }
            b'\n' => Some(b'\r'),
            b'\t' => Some(b'\t'),
            0..=0x1f | 0x7f => None,
            // UTF-8 encodes the C1 controls U+0080..U+009F, including single-character CSI, as C2 80..9F.
            0xc2 if bytes
                .get(index)
                .is_some_and(|next| (0x80..=0x9f).contains(next)) =>
            {
                index += 1;
                None
            }
            _ => Some(byte),
        };
        if let Some(output) = output {
            bytes[kept] = output;
            kept += 1;
        }
    }
    for byte in &mut bytes[kept..] {
        // SAFETY: byte is a valid exclusive reference; Secret clears only the bytes kept below.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    bytes.truncate(kept);
    if !bracketed {
        return text;
    }
    let mut framed = Secret(Vec::with_capacity(text.0.len() + 12));
    framed.0.extend_from_slice(b"\x1b[200~");
    framed.0.extend_from_slice(&text.0);
    framed.0.extend_from_slice(b"\x1b[201~");
    framed
}
pub(crate) fn set_clipboard_text(window: HWND, text: &str) -> Result<()> {
    let text = wide(text);
    // SAFETY: clipboard opened on its owning UI thread and closed by the guard.
    if unsafe { OpenClipboard(window) } == 0 {
        return Err("Clipboard unavailable.".into());
    }
    let _guard = Clipboard;
    // SAFETY: allocation is sized for the UTF-16 text; ownership transfers only on successful SetClipboardData.
    unsafe {
        let handle = GlobalAlloc(GMEM_MOVEABLE, text.len() * 2);
        if handle.is_null() {
            return Err("Cannot allocate clipboard text.".into());
        }
        let pointer = GlobalLock(handle).cast::<u16>();
        if pointer.is_null() {
            GlobalFree(handle);
            return Err("Cannot write clipboard.".into());
        }
        std::ptr::copy_nonoverlapping(text.as_ptr(), pointer, text.len());
        GlobalUnlock(handle);
        EmptyClipboard();
        if SetClipboardData(CF_UNICODETEXT, handle).is_null() {
            GlobalFree(handle);
            return Err("Cannot set clipboard text.".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paste_cannot_end_bracketed_paste_or_inject_controls() {
        let packet = |text: &str, bracketed| {
            std::mem::take(&mut paste_packet(Secret(text.into()), bracketed).0)
        };
        // The assessment's payload: an embedded end delimiter followed by a command line.
        assert_eq!(
            packet("echo harmless\x1b[201~\necho AUDIT_MARKER\n", true),
            b"\x1b[200~echo harmless[201~\recho AUDIT_MARKER\r\x1b[201~"
        );
        assert_eq!(
            packet("a\x1b[200~b\u{9b}201~c\u{85}d", true),
            b"\x1b[200~a[200~b201~cd\x1b[201~"
        );
        assert_eq!(packet("x\x03\x04\x1a\x15\x7f\0y\x08", false), b"xy");
        assert_eq!(
            packet("one\r\ntwo\nthree\rfour", false),
            b"one\rtwo\rthree\rfour"
        );
        let unicode = "ঢাকা 🚀 é\u{a0}\u{2028}\tend";
        assert_eq!(packet(unicode, false), unicode.as_bytes());
        assert_eq!(packet("", true), b"\x1b[200~\x1b[201~");
        let maximum = "a\x1b".repeat(16384);
        let framed = packet(&maximum, true);
        assert_eq!(framed.len(), 16384 + 12);
        assert_eq!(framed.iter().filter(|byte| **byte == 0x1b).count(), 2);
        assert!(framed.ends_with(b"\x1b[201~"));
    }

    #[test]
    fn native_terminal_routes_unicode_keys_and_pauses_user_input_when_detached() {
        // SAFETY: test owns a disposable parent and its terminal on this thread, destroyed before returning.
        unsafe {
            let parent = CreateWindowExW(
                0,
                wide("STATIC").as_ptr(),
                wide("").as_ptr(),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                900,
                600,
                null_mut(),
                null_mut(),
                GetModuleHandleW(null()),
                null(),
            );
            assert!(!parent.is_null());
            let terminal = create(parent, 1).unwrap();
            let (input, receiver) = std::sync::mpsc::sync_channel(10);
            attach(terminal, Some(input.clone()), true);
            SendMessageW(terminal, WM_CHAR, 'é' as usize, 0);
            SendMessageW(terminal, WM_CHAR, 0xd83d, 0);
            SendMessageW(terminal, WM_CHAR, 0xde80, 0);
            SendMessageW(terminal, WM_KEYDOWN, VK_UP as usize, 0);
            assert_eq!(receiver.recv().unwrap().0, "é".as_bytes());
            assert_eq!(receiver.recv().unwrap().0, "🚀".as_bytes());
            assert_eq!(receiver.recv().unwrap().0, b"\x1b[A");
            attach(terminal, None, false);
            SendMessageW(terminal, WM_CHAR, 'x' as usize, 0);
            assert!(receiver.try_recv().is_err());
            // Protocol replies remain serviced even while local keyboard input is detached.
            feed_session(terminal, b"\x1b[2;3H\x1b[6n", &input);
            assert_eq!(receiver.recv().unwrap().0, b"\x1b[2;3R");
            MoveWindow(terminal, 0, 0, 500, 300, 0);
            let (columns, rows) = size(terminal);
            assert!(columns < 80 && rows < 24);
            attach(terminal, Some(input), false);
            SendMessageW(terminal, WM_CHAR, 3, 0);
            assert_eq!(receiver.recv().unwrap().0, b"\x03");
            DestroyWindow(parent);
        }
    }
    #[test]
    fn command_shortcuts_insert_without_enter_and_reject_unavailable_input() {
        // SAFETY: this test owns a disposable parent and terminal on the current thread.
        unsafe {
            let parent = CreateWindowExW(
                0,
                wide("STATIC").as_ptr(),
                wide("").as_ptr(),
                WS_OVERLAPPEDWINDOW,
                0,
                0,
                900,
                600,
                null_mut(),
                null_mut(),
                GetModuleHandleW(null()),
                null(),
            );
            assert!(!parent.is_null());
            let terminal = create(parent, 1).unwrap();
            let (input, receiver) = std::sync::mpsc::sync_channel(1);
            attach(terminal, Some(input), false);
            for action in [
                crate::core::ReadOnlyAction::System,
                crate::core::ReadOnlyAction::Uptime,
                crate::core::ReadOnlyAction::Disk,
                crate::core::ReadOnlyAction::Memory,
            ] {
                insert_command(terminal, action.command()).unwrap();
                assert_eq!(receiver.recv().unwrap().0, action.command().as_bytes());
                assert!(receiver.try_recv().is_err());
            }
            for command in ["", "uptime\r", "uptime\n", "uptime\0", "\x1b[13~"] {
                assert!(insert_command(terminal, command).is_err());
                assert!(receiver.try_recv().is_err());
            }
            feed(terminal, b"\x1b[?2004h");
            insert_command(terminal, "df -h").unwrap();
            assert_eq!(receiver.recv().unwrap().0, b"\x1b[200~df -h\x1b[201~");
            insert_command(terminal, "uptime").unwrap();
            assert!(insert_command(terminal, "free -h").is_err());
            assert_eq!(receiver.recv().unwrap().0, b"\x1b[200~uptime\x1b[201~");
            assert!(receiver.try_recv().is_err());
            attach(terminal, None, false);
            assert!(insert_command(terminal, "df -h").is_err());
            assert!(receiver.try_recv().is_err());
            DestroyWindow(parent);
        }
    }

    #[test]
    fn navigation_keys_support_normal_application_and_modifier_modes() {
        assert_eq!(
            key_bytes(VK_UP, false, false, false, false).unwrap(),
            b"\x1b[A"
        );
        assert_eq!(
            key_bytes(VK_UP, false, false, false, true).unwrap(),
            b"\x1bOA"
        );
        assert_eq!(
            key_bytes(VK_RIGHT, false, false, true, false).unwrap(),
            b"\x1b[1;5C"
        );
        assert_eq!(
            key_bytes(VK_F5, false, false, false, false).unwrap(),
            b"\x1b[15~"
        );
    }
}
