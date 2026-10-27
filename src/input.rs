use std::ops::Range;

use termina::event::{KeyCode, KeyEvent, Modifiers};
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub struct Editor {
    text: String,
    cursor: usize,
    anchor: Option<usize>,
    offset: usize,
}

impl Editor {
    pub fn new(text: String) -> Self {
        Self {
            cursor: text.len(),
            anchor: Some(0),
            offset: 0,
            text,
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn selected(&self) -> &str {
        &self.text[self.selection()]
    }

    fn selection(&self) -> Range<usize> {
        let anchor = self.anchor.unwrap_or(self.cursor);
        anchor.min(self.cursor)..anchor.max(self.cursor)
    }

    fn move_to(&mut self, cursor: usize, selecting: bool) {
        if selecting {
            self.anchor.get_or_insert(self.cursor);
        } else {
            self.anchor = None;
        }
        self.cursor = cursor;
    }

    fn previous(&self, word: bool) -> usize {
        if word {
            self.text[..self.cursor]
                .unicode_word_indices()
                .next_back()
                .map_or(0, |(index, _)| index)
        } else {
            self.text[..self.cursor]
                .grapheme_indices(true)
                .next_back()
                .map_or(0, |(index, _)| index)
        }
    }

    fn next(&self, word: bool) -> usize {
        if word {
            self.text[self.cursor..]
                .unicode_word_indices()
                .next()
                .map_or(self.text.len(), |(index, word)| {
                    self.cursor + index + word.len()
                })
        } else {
            self.text[self.cursor..]
                .graphemes(true)
                .next()
                .map_or(self.cursor, |text| self.cursor + text.len())
        }
    }

    pub fn insert(&mut self, text: &str) {
        let selection = self.selection();
        self.offset = self.offset.min(selection.start);
        self.cursor = selection.start + text.len();
        self.text.replace_range(selection, text);
        self.anchor = None;
        self.cursor = self
            .text
            .grapheme_indices(true)
            .map(|(index, _)| index)
            .find(|index| *index >= self.cursor)
            .unwrap_or(self.text.len());
    }

    pub fn key(&mut self, key: KeyEvent) {
        let control = key
            .modifiers
            .intersects(Modifiers::CONTROL | Modifiers::SUPER)
            && !key.modifiers.contains(Modifiers::ALT);
        let selecting = key.modifiers.contains(Modifiers::SHIFT);
        let selection = self.selection();
        match key.code {
            KeyCode::Char('a') if control => {
                self.anchor = Some(0);
                self.cursor = self.text.len();
            }
            KeyCode::Left => {
                let cursor = if !selecting && !selection.is_empty() {
                    selection.start
                } else {
                    self.previous(control)
                };
                self.move_to(cursor, selecting);
            }
            KeyCode::Right => {
                let cursor = if !selecting && !selection.is_empty() {
                    selection.end
                } else {
                    self.next(control)
                };
                self.move_to(cursor, selecting);
            }
            KeyCode::Home => self.move_to(0, selecting),
            KeyCode::End => self.move_to(self.text.len(), selecting),
            KeyCode::Backspace | KeyCode::Delete => {
                if selection.is_empty() {
                    self.anchor = Some(if key.code == KeyCode::Backspace {
                        self.previous(control)
                    } else {
                        self.next(control)
                    });
                }
                self.insert("");
            }
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(Modifiers::CONTROL | Modifiers::ALT | Modifiers::SUPER)
                    || key.modifiers.contains(Modifiers::CONTROL | Modifiers::ALT)
                        && !key.modifiers.contains(Modifiers::SUPER) =>
            {
                self.insert(&character.to_string());
            }
            _ => {}
        }
    }

    pub fn view(&mut self, width: usize) -> (String, usize, Range<usize>) {
        if width == 0 {
            return (String::new(), 0, 0..0);
        }
        self.offset = self.offset.min(self.cursor);
        let mut start = self
            .text
            .grapheme_indices(true)
            .rfind(|(index, _)| *index <= self.offset)
            .map_or(0, |(index, _)| index);
        if visible(&self.text[start..self.cursor]).width() >= width {
            start = self.cursor;
            for (index, _) in self.text[..self.cursor].grapheme_indices(true).rev() {
                if visible(&self.text[index..self.cursor]).width() >= width {
                    break;
                }
                start = index;
            }
        }
        self.offset = start;
        let cursor = visible(&self.text[start..self.cursor]).width();
        let selection = self.selection();
        let mut highlighted = None;
        let mut text = String::new();
        for (index, grapheme) in self.text[start..].grapheme_indices(true) {
            let grapheme = visible(grapheme);
            let offset = text.len();
            text.push_str(&grapheme);
            if text.width() > width {
                text.truncate(offset);
                break;
            }
            if selection.contains(&(start + index)) {
                highlighted.get_or_insert(offset..text.len()).end = text.len();
            }
        }
        (text, cursor, highlighted.unwrap_or(0..0))
    }
}

pub fn visible(text: &str) -> String {
    let mut result = String::new();
    for character in text.chars() {
        match character {
            '\0'..='\u{1f}' => {
                result.push(char::from_u32(0x2400 + u32::from(character)).unwrap());
            }
            '\u{7f}' => result.push('␡'),
            character if character.is_control() => result.extend(character.escape_debug()),
            character => result.push(character),
        }
    }
    result
}

pub fn clip(text: &str, width: usize) -> String {
    let text = visible(text);
    if text.width() <= width {
        return text;
    }
    let mut result = String::new();
    for grapheme in text.graphemes(true) {
        let end = result.len();
        result.push_str(grapheme);
        if result.width() >= width {
            result.truncate(end);
            break;
        }
    }
    if width != 0 {
        result.push('…');
    }
    result
}

pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.lines() {
        let mut line = String::new();
        for grapheme in visible(paragraph).graphemes(true) {
            let end = line.len();
            line.push_str(grapheme);
            if line.width() > width && end != 0 {
                let remainder = line.split_off(end);
                lines.push(std::mem::replace(&mut line, remainder));
            }
        }
        lines.push(line);
    }
    lines
}
