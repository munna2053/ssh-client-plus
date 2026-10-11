//! Bounded VT display model. Output can change cells, never the clipboard, files, or processes.
use std::collections::VecDeque;

pub const MAX_COLUMNS: usize = 240;
pub const MAX_ROWS: usize = 120;
pub const MAX_HISTORY: usize = 1000;
pub const DEFAULT_FOREGROUND: u32 = 0xd8e2f0;
pub const DEFAULT_BACKGROUND: u32 = 0x0b1018;
const PALETTE: [u32; 16] = [
    0x18212e, 0xf47067, 0x7ee787, 0xe3b341, 0x79b8ff, 0xd2a8ff, 0x56d4dd, 0xc8d3e3, 0x68778d,
    0xff938a, 0xb3f5b7, 0xffdf8a, 0xa6d0ff, 0xe0c2ff, 0x9be9f1, 0xffffff,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    pub foreground: u32,
    pub background: u32,
    pub bold: bool,
    pub underline: bool,
    pub inverse: bool,
}
impl Default for Style {
    fn default() -> Self {
        Self {
            foreground: DEFAULT_FOREGROUND,
            background: DEFAULT_BACKGROUND,
            bold: false,
            underline: false,
            inverse: false,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cell {
    pub text: String,
    pub style: Style,
    pub continuation: bool,
}
impl Cell {
    pub fn glyph(&self) -> &str {
        if self.text.is_empty() {
            " "
        } else {
            &self.text
        }
    }
}

struct Screen {
    lines: Vec<Vec<Cell>>,
    row: usize,
    column: usize,
    saved: (usize, usize),
    top: usize,
    bottom: usize,
    wrap_pending: bool,
}
impl Screen {
    fn new(columns: usize, rows: usize) -> Self {
        Self {
            lines: vec![vec![Cell::default(); columns]; rows],
            row: 0,
            column: 0,
            saved: (0, 0),
            top: 0,
            bottom: rows - 1,
            wrap_pending: false,
        }
    }
    fn resize(&mut self, columns: usize, rows: usize) {
        self.lines.resize(rows, vec![Cell::default(); columns]);
        for line in &mut self.lines {
            line.resize(columns, Cell::default());
            if line.last().is_some_and(|cell| cell.continuation) {
                line[columns - 1] = Cell::default();
            }
        }
        self.row = self.row.min(rows - 1);
        self.column = self.column.min(columns - 1);
        self.saved.0 = self.saved.0.min(rows - 1);
        self.saved.1 = self.saved.1.min(columns - 1);
        self.top = 0;
        self.bottom = rows - 1;
        self.wrap_pending = false;
    }
}

enum Parser {
    Ground,
    Escape,
    Charset,
    Csi(Vec<u8>),
    String { osc: bool, escaped: bool },
}

pub struct Terminal {
    pub columns: usize,
    pub rows: usize,
    screen: Screen,
    normal: Option<Screen>,
    history: VecDeque<Vec<Cell>>,
    style: Style,
    parser: Parser,
    utf8: Vec<u8>,
    pub application_cursor: bool,
    pub bracketed_paste: bool,
    pub cursor_visible: bool,
    wrap: bool,
    origin: bool,
    tabs: Vec<bool>,
    saved_style: Style,
}

impl Terminal {
    pub fn new(columns: usize, rows: usize) -> Self {
        let columns = columns.clamp(2, MAX_COLUMNS);
        let rows = rows.clamp(2, MAX_ROWS);
        Self {
            columns,
            rows,
            screen: Screen::new(columns, rows),
            normal: None,
            history: VecDeque::new(),
            style: Style::default(),
            parser: Parser::Ground,
            utf8: Vec::with_capacity(4),
            application_cursor: false,
            bracketed_paste: false,
            cursor_visible: true,
            wrap: true,
            origin: false,
            tabs: (0..columns).map(|index| index % 8 == 0).collect(),
            saved_style: Style::default(),
        }
    }
    pub fn resize(&mut self, columns: usize, rows: usize) {
        self.columns = columns.clamp(2, MAX_COLUMNS);
        self.rows = rows.clamp(2, MAX_ROWS);
        self.screen.resize(self.columns, self.rows);
        if let Some(normal) = &mut self.normal {
            normal.resize(self.columns, self.rows);
        }
        for line in &mut self.history {
            line.resize(self.columns, Cell::default());
        }
        self.tabs.resize(self.columns, false);
        for index in (8..self.columns).step_by(8) {
            self.tabs[index] = true;
        }
    }
    pub fn reset(&mut self) {
        *self = Self::new(self.columns, self.rows);
    }
    pub fn history_len(&self) -> usize {
        if self.normal.is_some() {
            0
        } else {
            self.history.len()
        }
    }
    pub fn cursor(&self) -> (usize, usize) {
        (self.screen.row, self.screen.column)
    }
    pub fn cell(&self, row: usize, column: usize, scroll: usize) -> Option<&Cell> {
        if row >= self.rows || column >= self.columns {
            return None;
        }
        let history = self.history_len();
        let index = history + row - scroll.min(history);
        if index < history {
            self.history.get(index)?.get(column)
        } else {
            self.screen.lines.get(index - history)?.get(column)
        }
    }
    pub fn selection(&self, start: (usize, usize), end: (usize, usize), scroll: usize) -> String {
        let (start, end) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };
        let mut result = String::new();
        for row in start.0.min(self.rows - 1)..=end.0.min(self.rows - 1) {
            let first = if row == start.0 {
                start.1.min(self.columns - 1)
            } else {
                0
            };
            let last = if row == end.0 {
                end.1.min(self.columns - 1)
            } else {
                self.columns - 1
            };
            let mut line = String::new();
            for column in first..=last {
                if let Some(cell) = self.cell(row, column, scroll)
                    && !cell.continuation
                {
                    line.push_str(cell.glyph());
                }
            }
            result.push_str(line.trim_end_matches(' '));
            if row < end.0 {
                result.push('\n');
            }
            if result.len() > 32768 {
                let mut end = 32768;
                while !result.is_char_boundary(end) {
                    end -= 1;
                }
                result.truncate(end);
                break;
            }
        }
        result
    }
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut replies = Vec::new();
        for &byte in bytes {
            let parser = std::mem::replace(&mut self.parser, Parser::Ground);
            match parser {
                Parser::Ground => self.ground(byte),
                Parser::Escape => match byte {
                    b'[' => self.parser = Parser::Csi(Vec::with_capacity(32)),
                    b']' => {
                        self.parser = Parser::String {
                            osc: true,
                            escaped: false,
                        }
                    }
                    b'P' | b'_' | b'^' => {
                        self.parser = Parser::String {
                            osc: false,
                            escaped: false,
                        }
                    }
                    b'(' | b')' | b'*' | b'+' => self.parser = Parser::Charset,
                    b'7' => {
                        self.screen.saved = self.cursor();
                        self.saved_style = self.style;
                    }
                    b'8' => {
                        (self.screen.row, self.screen.column) = self.screen.saved;
                        self.style = self.saved_style;
                        self.screen.wrap_pending = false;
                    }
                    b'D' => self.index(),
                    b'E' => {
                        self.screen.column = 0;
                        self.index();
                    }
                    b'M' => self.reverse_index(),
                    b'H' => self.tabs[self.screen.column] = true,
                    b'c' => self.reset(),
                    b'=' => self.application_cursor = true,
                    b'>' => self.application_cursor = false,
                    0x1b => self.parser = Parser::Escape,
                    _ => {}
                },
                Parser::Charset => {}
                Parser::Csi(mut sequence) => {
                    if byte == 0x1b {
                        self.parser = Parser::Escape;
                    } else if (0x40..=0x7e).contains(&byte) {
                        self.csi(&sequence, byte, &mut replies);
                    } else if matches!(byte, 0x18 | 0x1a) {
                    } else if sequence.len() < 128 {
                        sequence.push(byte);
                        self.parser = Parser::Csi(sequence);
                    }
                }
                Parser::String { osc, escaped } => {
                    if !((osc && byte == 7)
                        || (escaped && byte == b'\\')
                        || matches!(byte, 0x18 | 0x1a))
                    {
                        self.parser = Parser::String {
                            osc,
                            escaped: byte == 0x1b,
                        };
                    }
                }
            }
        }
        replies
    }
    fn ground(&mut self, byte: u8) {
        if byte < 0x20 || byte == 0x7f {
            if !self.utf8.is_empty() {
                self.utf8.clear();
                self.put('\u{fffd}');
            }
            match byte {
                0x1b => self.parser = Parser::Escape,
                b'\r' => {
                    self.screen.column = 0;
                    self.screen.wrap_pending = false;
                }
                b'\n' | 0x0b | 0x0c => self.index(),
                8 => {
                    self.screen.column = self.screen.column.saturating_sub(1);
                    self.screen.wrap_pending = false;
                }
                b'\t' => {
                    self.screen.column = (self.screen.column + 1..self.columns)
                        .find(|&column| self.tabs[column])
                        .unwrap_or(self.columns - 1);
                    self.screen.wrap_pending = false;
                }
                _ => {}
            }
        } else if byte.is_ascii() {
            if !self.utf8.is_empty() {
                self.utf8.clear();
                self.put('\u{fffd}');
            }
            self.put(byte as char);
        } else {
            self.utf8.push(byte);
            match std::str::from_utf8(&self.utf8) {
                Ok(value) => {
                    let character = value.chars().next().unwrap();
                    self.utf8.clear();
                    self.put(character);
                }
                Err(error) if error.error_len().is_some() || self.utf8.len() >= 4 => {
                    self.utf8.clear();
                    self.put('\u{fffd}');
                }
                _ => {}
            }
        }
    }
    fn put(&mut self, character: char) {
        let width = character_width(character);
        if width == 0 {
            let mut column = if self.screen.wrap_pending {
                self.screen.column
            } else {
                self.screen.column.saturating_sub(1)
            };
            if self.screen.lines[self.screen.row][column].continuation {
                column = column.saturating_sub(1);
            }
            let cell = &mut self.screen.lines[self.screen.row][column];
            if cell.text.len() + character.len_utf8() <= 64 {
                cell.text.push(character);
            }
            return;
        }
        if self.screen.wrap_pending || (width == 2 && self.screen.column == self.columns - 1) {
            if self.wrap {
                self.screen.column = 0;
                self.index();
            }
            self.screen.wrap_pending = false;
        }
        let column = self.screen.column;
        let row = self.screen.row;
        // Erase both halves when overwriting a wide character.
        if self.screen.lines[row][column].continuation && column > 0 {
            self.screen.lines[row][column - 1] = Cell::default();
        }
        if column + 1 < self.columns && self.screen.lines[row][column + 1].continuation {
            self.screen.lines[row][column + 1] = Cell::default();
        }
        self.screen.lines[row][column] = Cell {
            text: character.to_string(),
            style: self.style,
            continuation: false,
        };
        if width == 2 && column + 1 < self.columns {
            self.screen.lines[row][column + 1] = Cell {
                text: String::new(),
                style: self.style,
                continuation: true,
            };
        }
        if column + width >= self.columns {
            self.screen.column = self.columns - 1;
            self.screen.wrap_pending = self.wrap;
        } else {
            self.screen.column += width;
        }
    }
    fn blank_line(&self) -> Vec<Cell> {
        vec![
            Cell {
                style: self.style,
                ..Cell::default()
            };
            self.columns
        ]
    }
    fn scroll_up(&mut self, top: usize, bottom: usize, count: usize) {
        for _ in 0..count.min(bottom - top + 1) {
            let removed = self.screen.lines.remove(top);
            self.screen.lines.insert(bottom, self.blank_line());
            if self.normal.is_none() && top == 0 && bottom == self.rows - 1 {
                if self.history.len() == MAX_HISTORY {
                    self.history.pop_front();
                }
                self.history.push_back(removed);
            }
        }
    }
    fn scroll_down(&mut self, top: usize, bottom: usize, count: usize) {
        for _ in 0..count.min(bottom - top + 1) {
            self.screen.lines.remove(bottom);
            self.screen.lines.insert(top, self.blank_line());
        }
    }
    fn index(&mut self) {
        if self.screen.row == self.screen.bottom {
            self.scroll_up(self.screen.top, self.screen.bottom, 1);
        } else {
            self.screen.row = (self.screen.row + 1).min(self.rows - 1);
        }
        self.screen.wrap_pending = false;
    }
    fn reverse_index(&mut self) {
        if self.screen.row == self.screen.top {
            self.scroll_down(self.screen.top, self.screen.bottom, 1);
        } else {
            self.screen.row = self.screen.row.saturating_sub(1);
        }
        self.screen.wrap_pending = false;
    }
    fn csi(&mut self, sequence: &[u8], final_byte: u8, replies: &mut Vec<u8>) {
        let private = sequence
            .first()
            .copied()
            .filter(|byte| matches!(byte, b'?' | b'>' | b'!'));
        let body = if private.is_some() {
            &sequence[1..]
        } else {
            sequence
        };
        if body
            .iter()
            .any(|byte| !byte.is_ascii_digit() && *byte != b';')
        {
            return;
        }
        let values: Vec<usize> = body
            .split(|byte| *byte == b';')
            .take(32)
            .map(|part| {
                part.iter().fold(0usize, |number, byte| {
                    (number * 10 + (byte - b'0') as usize).min(99999)
                })
            })
            .collect();
        let value = |index: usize, default: usize| {
            values
                .get(index)
                .copied()
                .filter(|value| *value != 0)
                .unwrap_or(default)
        };
        let amount = value(0, 1);
        let (top, bottom) = if self.origin {
            (self.screen.top, self.screen.bottom)
        } else {
            (0, self.rows - 1)
        };
        if !matches!(final_byte, b'm' | b'n' | b'c' | b'h' | b'l') {
            self.screen.wrap_pending = false;
        }
        match final_byte {
            b'A' => self.screen.row = self.screen.row.saturating_sub(amount).max(top),
            b'B' | b'e' => self.screen.row = self.screen.row.saturating_add(amount).min(bottom),
            b'C' | b'a' => {
                self.screen.column = self
                    .screen
                    .column
                    .saturating_add(amount)
                    .min(self.columns - 1)
            }
            b'D' => self.screen.column = self.screen.column.saturating_sub(amount),
            b'E' => {
                self.screen.row = self.screen.row.saturating_add(amount).min(bottom);
                self.screen.column = 0;
            }
            b'F' => {
                self.screen.row = self.screen.row.saturating_sub(amount).max(top);
                self.screen.column = 0;
            }
            b'G' | b'`' => self.screen.column = amount.saturating_sub(1).min(self.columns - 1),
            b'd' => self.screen.row = (top + amount.saturating_sub(1)).min(bottom),
            b'H' | b'f' => {
                self.screen.row = (top + amount.saturating_sub(1)).min(bottom);
                self.screen.column = value(1, 1).saturating_sub(1).min(self.columns - 1);
            }
            b'J' => self.erase_display(values[0]),
            b'K' => self.erase_line(values[0]),
            b'X' => {
                let row = self.screen.row;
                self.erase_range(
                    row,
                    self.screen.column,
                    (self.screen.column + amount).min(self.columns),
                );
            }
            b'@' | b'P' => {
                let column = self.screen.column;
                let count = amount.min(self.columns - column);
                let blank = Cell {
                    style: self.style,
                    ..Cell::default()
                };
                let line = &mut self.screen.lines[self.screen.row];
                for _ in 0..count {
                    if final_byte == b'@' {
                        line.insert(column, blank.clone());
                        line.pop();
                    } else {
                        line.remove(column);
                        line.push(blank.clone());
                    }
                }
            }
            b'L' | b'M'
                if self.screen.row >= self.screen.top && self.screen.row <= self.screen.bottom =>
            {
                if final_byte == b'L' {
                    self.scroll_down(self.screen.row, self.screen.bottom, amount);
                } else {
                    self.scroll_up(self.screen.row, self.screen.bottom, amount);
                }
            }
            b'S' => self.scroll_up(self.screen.top, self.screen.bottom, amount),
            b'T' => self.scroll_down(self.screen.top, self.screen.bottom, amount),
            b'r' if private.is_none() => {
                let top = amount.saturating_sub(1).min(self.rows - 1);
                let bottom = value(1, self.rows).saturating_sub(1).min(self.rows - 1);
                if top < bottom {
                    self.screen.top = top;
                    self.screen.bottom = bottom;
                    self.screen.row = if self.origin { top } else { 0 };
                    self.screen.column = 0;
                }
            }
            b's' => {
                self.screen.saved = self.cursor();
                self.saved_style = self.style;
            }
            b'u' => {
                (self.screen.row, self.screen.column) = self.screen.saved;
                self.style = self.saved_style;
            }
            b'm' => self.sgr(&values),
            b'g' => match values[0] {
                0 => self.tabs[self.screen.column] = false,
                3 => self.tabs.fill(false),
                _ => {}
            },
            b'h' | b'l' if private == Some(b'?') => {
                for mode in values {
                    self.mode(mode, final_byte == b'h');
                }
            }
            b'n' if values[0] == 5 && private.is_none() => replies.extend_from_slice(b"\x1b[0n"),
            b'n' if values[0] == 6 => {
                replies.extend_from_slice(
                    format!(
                        "\x1b[{}{};{}R",
                        if private == Some(b'?') { "?" } else { "" },
                        self.screen.row.saturating_sub(if self.origin {
                            self.screen.top
                        } else {
                            0
                        }) + 1,
                        self.screen.column + 1
                    )
                    .as_bytes(),
                );
            }
            b'c' if private == Some(b'>') => replies.extend_from_slice(b"\x1b[>0;1;0c"),
            b'c' => replies.extend_from_slice(b"\x1b[?1;2c"),
            _ => {}
        }
        // A hostile stream cannot cause an unbounded response batch.
        replies.truncate(4096);
    }
    fn erase_range(&mut self, row: usize, start: usize, end: usize) {
        for cell in &mut self.screen.lines[row][start..end] {
            *cell = Cell {
                style: self.style,
                ..Cell::default()
            };
        }
    }
    fn erase_line(&mut self, mode: usize) {
        let row = self.screen.row;
        match mode {
            0 => self.erase_range(row, self.screen.column, self.columns),
            1 => self.erase_range(row, 0, self.screen.column + 1),
            2 => self.erase_range(row, 0, self.columns),
            _ => {}
        }
    }
    fn erase_display(&mut self, mode: usize) {
        let row = self.screen.row;
        match mode {
            0 => {
                self.erase_line(0);
                for row in row + 1..self.rows {
                    self.erase_range(row, 0, self.columns);
                }
            }
            1 => {
                for row in 0..row {
                    self.erase_range(row, 0, self.columns);
                }
                self.erase_line(1);
            }
            2 => {
                for row in 0..self.rows {
                    self.erase_range(row, 0, self.columns);
                }
            }
            3 => self.history.clear(),
            _ => {}
        }
    }
    fn mode(&mut self, mode: usize, enabled: bool) {
        match mode {
            1 => self.application_cursor = enabled,
            6 => {
                self.origin = enabled;
                self.screen.row = if enabled { self.screen.top } else { 0 };
                self.screen.column = 0;
            }
            7 => self.wrap = enabled,
            25 => self.cursor_visible = enabled,
            2004 => self.bracketed_paste = enabled,
            47 | 1047 | 1049 => {
                if enabled && self.normal.is_none() {
                    self.normal = Some(std::mem::replace(
                        &mut self.screen,
                        Screen::new(self.columns, self.rows),
                    ));
                    self.saved_style = self.style;
                } else if !enabled && let Some(normal) = self.normal.take() {
                    self.screen = normal;
                    self.style = self.saved_style;
                }
            }
            _ => {}
        }
    }
    fn sgr(&mut self, values: &[usize]) {
        let mut index = 0;
        while index < values.len() {
            match values[index] {
                0 => self.style = Style::default(),
                1 => self.style.bold = true,
                22 => self.style.bold = false,
                4 => self.style.underline = true,
                24 => self.style.underline = false,
                7 => self.style.inverse = true,
                27 => self.style.inverse = false,
                30..=37 => self.style.foreground = PALETTE[values[index] - 30],
                40..=47 => self.style.background = PALETTE[values[index] - 40],
                90..=97 => self.style.foreground = PALETTE[values[index] - 90 + 8],
                100..=107 => self.style.background = PALETTE[values[index] - 100 + 8],
                39 => self.style.foreground = DEFAULT_FOREGROUND,
                49 => self.style.background = DEFAULT_BACKGROUND,
                38 | 48 => {
                    let foreground = values[index] == 38;
                    let color = match values.get(index + 1) {
                        Some(5) if index + 2 < values.len() => {
                            index += 2;
                            Some(indexed_color(values[index].min(255)))
                        }
                        Some(2) if index + 4 < values.len() => {
                            let color = (values[index + 2].min(255) << 16)
                                | (values[index + 3].min(255) << 8)
                                | values[index + 4].min(255);
                            index += 4;
                            Some(color as u32)
                        }
                        _ => None,
                    };
                    if let Some(color) = color {
                        if foreground {
                            self.style.foreground = color;
                        } else {
                            self.style.background = color;
                        }
                    }
                }
                _ => {}
            }
            index += 1;
        }
    }
}

fn indexed_color(index: usize) -> u32 {
    if index < 16 {
        PALETTE[index]
    } else if index >= 232 {
        let value = (8 + (index - 232) * 10) as u32;
        value * 0x010101
    } else {
        let value = index - 16;
        let level = |component: usize| {
            if component == 0 {
                0
            } else {
                55 + component * 40
            }
        };
        ((level(value / 36) << 16) | (level((value / 6) % 6) << 8) | level(value % 6)) as u32
    }
}

fn character_width(character: char) -> usize {
    let code = character as u32;
    if matches!(code, 0x0300..=0x036f | 0x0483..=0x0489 | 0x0591..=0x05bd | 0x0610..=0x061a | 0x064b..=0x065f | 0x093a..=0x094d | 0x0981..=0x0983 | 0x09bc..=0x09cd | 0x1ab0..=0x1aff | 0x1dc0..=0x1dff | 0x200b..=0x200f | 0x20d0..=0x20ff | 0xfe00..=0xfe0f | 0xfe20..=0xfe2f | 0xe0100..=0xe01ef)
    {
        0
    } else if matches!(code, 0x1100..=0x115f | 0x2329..=0x232a | 0x2e80..=0xa4cf | 0xac00..=0xd7a3 | 0xf900..=0xfaff | 0xfe10..=0xfe19 | 0xfe30..=0xfe6f | 0xff01..=0xff60 | 0xffe0..=0xffe6 | 0x1f300..=0x1faff | 0x20000..=0x3fffd)
    {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn line(terminal: &Terminal, row: usize) -> String {
        (0..terminal.columns)
            .filter_map(|column| terminal.cell(row, column, 0))
            .filter(|cell| !cell.continuation)
            .map(Cell::glyph)
            .collect::<String>()
            .trim_end()
            .into()
    }
    #[test]
    fn fragmented_utf8_escape_sequences_and_shell_editing_render_correctly() {
        let mut terminal = Terminal::new(24, 4);
        for byte in "prompt> café 漢\u{301}".as_bytes() {
            terminal.feed(&[*byte]);
        }
        assert_eq!(line(&terminal, 0), "prompt> café 漢\u{301}");
        terminal.feed(b"\r\x1b[2K\x1b[38;2;100;150;200mready\x1b[0m\r\nnext\x1b[2DXX");
        assert_eq!(line(&terminal, 0), "ready");
        assert_eq!(line(&terminal, 1), "neXX");
        assert_eq!(terminal.cell(0, 0, 0).unwrap().style.foreground, 0x6496c8);
    }
    #[test]
    fn alternate_screen_and_scroll_margins_preserve_shell_and_history() {
        let mut terminal = Terminal::new(12, 4);
        terminal.feed(b"shell\r\n");
        terminal.feed(b"\x1b[?1049h\x1b[2J\x1b[1;1Heditor\x1b[2;4r\x1b[4;1Hbottom\n\x1b[?1049l");
        assert_eq!(line(&terminal, 0), "shell");
        assert_eq!(terminal.cursor(), (1, 0));
        for _ in 0..MAX_HISTORY + 10 {
            terminal.feed(b"line\r\n");
        }
        assert_eq!(terminal.history_len(), MAX_HISTORY);
        terminal.resize(1, usize::MAX);
        assert_eq!((terminal.columns, terminal.rows), (2, MAX_ROWS));
    }
    #[test]
    fn hostile_control_strings_are_ignored_and_state_stays_bounded() {
        let mut terminal = Terminal::new(20, 4);
        terminal.feed(b"before\x1b]52;c;clipboard attack");
        terminal.feed(&vec![b'x'; 20000]);
        terminal.feed(b"\x1b\\after");
        assert_eq!(line(&terminal, 0), "beforeafter");
        terminal.feed(b"\x1b[999999999999999999999999999999999;999999999999H!");
        assert_eq!(terminal.cursor(), (3, 19));
        terminal.feed(b"\x1b[1;1H");
        for _ in 0..5000 {
            terminal.feed("e\u{301}".as_bytes());
        }
        assert!(
            terminal
                .screen
                .lines
                .iter()
                .flatten()
                .all(|cell| cell.text.len() <= 64)
        );
        terminal.feed(b"\x1b[2;3H");
        assert_eq!(terminal.feed(b"\x1b[6n"), b"\x1b[2;3R");
        // Restoring a cursor saved before origin mode must not underflow a status reply.
        terminal.feed(b"\x1b[1;1H\x1b7\x1b[3;4r\x1b[?6h\x1b8");
        assert_eq!(terminal.feed(b"\x1b[6n"), b"\x1b[1;1R");
    }
}
