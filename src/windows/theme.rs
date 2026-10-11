use crate::Result;
use windows_sys::Win32::{
    Foundation::{COLORREF, RECT},
    Graphics::Gdi::*,
};

pub const CANVAS: u32 = 0x0b1018;
pub const PANEL: u32 = 0x111a27;
pub const INPUT: u32 = 0x172233;
pub const BORDER: u32 = 0x273549;
pub const TEXT: u32 = 0xe7edf7;
pub const MUTED: u32 = 0x92a3bc;
pub const ACCENT: u32 = 0x8175ff;
pub const SELECTED: u32 = 0x263654;
pub const GREEN: u32 = 0x7ee787;
pub fn color(rgb: u32) -> COLORREF {
    (rgb & 0xff) << 16 | (rgb & 0xff00) | (rgb >> 16) & 0xff
}
pub fn scale(value: i32, dpi: u32) -> i32 {
    value * dpi as i32 / 96
}

pub struct Object(pub HGDIOBJ);
impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: owns a successfully created GDI resource that is no longer selected.
        unsafe {
            DeleteObject(self.0);
        }
    }
}
pub fn font(face: &str, size: i32, dpi: u32, bold: bool) -> Result<Object> {
    let face = super::wide(face);
    // SAFETY: null-terminated font face remains alive; all other arguments are scalar font settings.
    let font = unsafe {
        CreateFontW(
            -scale(size, dpi),
            0,
            0,
            0,
            if bold { FW_SEMIBOLD } else { FW_NORMAL } as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            OUT_DEFAULT_PRECIS as u32,
            CLIP_DEFAULT_PRECIS as u32,
            CLEARTYPE_QUALITY as u32,
            FIXED_PITCH as u32 | FF_DONTCARE as u32,
            face.as_ptr(),
        )
    };
    if font.is_null() {
        return Err("Cannot create the desktop font.".into());
    }
    Ok(Object(font))
}

pub struct Theme {
    pub dpi: u32,
    pub body: Object,
    pub title: Object,
    pub heading: Object,
    pub canvas: Object,
    pub panel: Object,
    pub input: Object,
}
impl Theme {
    pub fn new(dpi: u32) -> Result<Self> {
        fn brush(rgb: u32) -> Result<Object> {
            // SAFETY: creates an owned brush from a valid RGB value.
            let brush = unsafe { CreateSolidBrush(color(rgb)) };
            if brush.is_null() {
                return Err("Cannot create desktop colours.".into());
            }
            Ok(Object(brush))
        }
        Ok(Self {
            dpi,
            body: font("Segoe UI", 15, dpi, false)?,
            title: font("Segoe UI", 26, dpi, true)?,
            heading: font("Segoe UI", 19, dpi, true)?,
            canvas: brush(CANVAS)?,
            panel: brush(PANEL)?,
            input: brush(INPUT)?,
        })
    }
}

pub(crate) fn fill(dc: HDC, rect: &RECT, rgb: u32) {
    // SAFETY: temporary brush is owned and FillRect does not select it into a DC.
    unsafe {
        let brush = CreateSolidBrush(color(rgb));
        if !brush.is_null() {
            FillRect(dc, rect, brush);
            DeleteObject(brush);
        }
    }
}
pub(crate) fn rounded(dc: HDC, rect: &RECT, rgb: u32, radius: i32) {
    // SAFETY: temporary owned brush is deselected before deletion; stock pen stays OS-owned.
    unsafe {
        let brush = CreateSolidBrush(color(rgb));
        if brush.is_null() {
            return;
        }
        let old_brush = SelectObject(dc, brush);
        let old_pen = SelectObject(dc, GetStockObject(NULL_PEN));
        RoundRect(
            dc,
            rect.left,
            rect.top,
            rect.right,
            rect.bottom,
            radius,
            radius,
        );
        SelectObject(dc, old_pen);
        SelectObject(dc, old_brush);
        DeleteObject(brush);
    }
}
pub(crate) fn text(dc: HDC, rect: RECT, value: &str, font: HGDIOBJ, rgb: u32, flags: u32) {
    let mut text = super::wide(value);
    let mut rect = rect;
    // SAFETY: text and rectangle remain alive; font is borrowed and restored before returning.
    unsafe {
        let old = SelectObject(dc, font);
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, color(rgb));
        DrawTextW(
            dc,
            text.as_mut_ptr(),
            (text.len() - 1) as i32,
            &mut rect,
            flags,
        );
        SelectObject(dc, old);
    }
}
