use std::fmt::Write;

use icu_properties::{
    CodePointMapData, PropertyNamesLong, PropertyParser,
    props::{GeneralCategoryGroup, Script},
};
use regex_syntax::{ParserBuilder, hir::Hir};

use crate::Result;

pub fn parse(text: &str) -> Result<Hir> {
    let text = Normalizer { text }.expression()?;
    ParserBuilder::new()
        .nest_limit(u32::MAX)
        .build()
        .parse(&text)
        .map_err(|error| {
            let message = match &error {
                regex_syntax::Error::Parse(error) => error.kind().to_string(),
                regex_syntax::Error::Translate(error) => error.kind().to_string(),
                _ => error.to_string(),
            };
            format!("正则表达式格式不正确：{message}").into()
        })
}

struct Normalizer<'a> {
    text: &'a str,
}

impl Normalizer<'_> {
    fn expression(&mut self) -> Result<String> {
        let mut output = String::new();
        let mut repeated = false;
        while !self.text.is_empty() {
            let character = self.next()?;
            let repetition = match character {
                '*' | '+' | '?' => Some(character.to_string()),
                '{' => self.repetition(),
                _ => None,
            };
            if let Some(repetition) = repetition {
                if repeated {
                    return Err("正则表达式中有连续的重复符".into());
                }
                output.push_str(&repetition);
                if self.take("?") {
                    output.push('?');
                }
                repeated = true;
                continue;
            }
            repeated = false;
            match character {
                '\\' => {
                    if self.take("Q") {
                        let (literal, rest) =
                            self.text.split_once("\\E").unwrap_or((self.text, ""));
                        output.push_str(&regex_syntax::escape(literal));
                        self.text = rest;
                    } else if let Some(class) = self.character_group()? {
                        output.push_str(&class);
                    } else {
                        match self.text.chars().next() {
                            Some('b' | 'B') => {
                                write!(output, "(?-u:\\{})", self.next()?).unwrap();
                            }
                            Some('A' | 'z') => {
                                output.push('\\');
                                output.push(self.next()?);
                            }
                            _ => {
                                let rune = self.escape()?;
                                output.push_str(&range(rune, rune));
                            }
                        }
                    }
                }
                '[' => output.push_str(&self.class()?),
                '(' => output.push_str(&self.group()?),
                '.' | '^' | '$' | ')' | '|' => output.push(character),
                _ => output.push_str(&regex_syntax::escape(&character.to_string())),
            }
        }
        Ok(output)
    }

    fn class(&mut self) -> Result<String> {
        let negative = self.take("^");
        let mut output = String::new();
        let mut first = true;
        while first || !self.take("]") {
            first = false;
            if self.text.starts_with("[:")
                && let Some(end) = self.text.find(":]")
            {
                output.push('[');
                output.push_str(&self.text[..end + 2]);
                output.push(']');
                self.text = &self.text[end + 2..];
                continue;
            }
            if self.take("\\") {
                if let Some(class) = self.character_group()? {
                    output.push_str(&class);
                    continue;
                }
                let low = self.escape()?;
                self.class_range(low, &mut output)?;
            } else {
                let low = self.next()? as u32;
                self.class_range(low, &mut output)?;
            }
        }
        Ok(format!("[{}{output}]", if negative { "^" } else { "" }))
    }

    fn class_range(&mut self, low: u32, output: &mut String) -> Result<()> {
        let high = if self.text.starts_with('-') && !self.text.starts_with("-]") {
            self.next()?;
            if self.take("\\") {
                self.escape()?
            } else {
                self.next()? as u32
            }
        } else {
            low
        };
        if high < low {
            return Err("正则表达式的字符范围需要按从小到大填写".into());
        }
        output.push_str(&range(low, high));
        Ok(())
    }

    fn character_group(&mut self) -> Result<Option<String>> {
        let class = match self.text.chars().next() {
            Some('d') => "[0-9]",
            Some('D') => "[^0-9]",
            Some('s') => "[\\t\\n\\f\\r ]",
            Some('S') => "[^\\t\\n\\f\\r ]",
            Some('w') => "[0-9A-Za-z_]",
            Some('W') => "[^0-9A-Za-z_]",
            Some('p' | 'P') => return self.unicode().map(Some),
            _ => return Ok(None),
        };
        self.next()?;
        Ok(Some(class.to_owned()))
    }

    fn unicode(&mut self) -> Result<String> {
        let mut negative = self.next()? == 'P';
        let name = if self.take("{") {
            let (name, rest) = self
                .text
                .split_once('}')
                .ok_or("Unicode 字符类缺少右花括号")?;
            self.text = rest;
            name.to_owned()
        } else {
            self.next()?.to_string()
        };
        let name = if let Some(name) = name.strip_prefix('^') {
            negative = !negative;
            name
        } else {
            &name
        };
        let key = canonical(name);
        let property = match key.as_str() {
            "any" => "Any".to_owned(),
            "ascii" => "ASCII".to_owned(),
            "assigned" => "Assigned".to_owned(),
            _ => {
                if name.chars().any(|c| c.is_ascii_whitespace() && c != ' ') {
                    return Err(format!("找不到 Unicode 字符类：{name}").into());
                }
                if PropertyParser::<GeneralCategoryGroup>::new()
                    .get_loose(name)
                    .is_some()
                {
                    format!("gc={key}")
                } else if let Some(script) = PropertyParser::<Script>::new().get_loose(name)
                    && script != Script::Unknown
                    && CodePointMapData::<Script>::new()
                        .iter_ranges_for_value(script)
                        .next()
                        .is_some()
                    && let Some(long) = PropertyNamesLong::<Script>::new().get(script)
                    && key == canonical(long)
                {
                    format!("sc={long}")
                } else {
                    return Err(format!("找不到 Unicode 字符类：{name}").into());
                }
            }
        };
        Ok(format!(
            "\\{}{{{property}}}",
            if negative { 'P' } else { 'p' }
        ))
    }

    fn group(&mut self) -> Result<String> {
        if !self.take("?") {
            return Ok("(?:".to_owned());
        }
        if self.take("P<") || self.take("<") {
            let (name, rest) = self
                .text
                .split_once('>')
                .ok_or("正则表达式的命名组缺少 >")?;
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!("正则表达式的分组名称不正确：{name}").into());
            }
            self.text = rest;
            return Ok("(?:".to_owned());
        }
        let mut flags = [None; 4];
        let mut enabled = true;
        let mut seen = false;
        loop {
            let character = self.next()?;
            match character {
                'i' | 'm' | 's' | 'U' => {
                    let index = "imsU".find(character).unwrap();
                    flags[index] = Some(enabled);
                    seen = true;
                }
                '-' if enabled => {
                    enabled = false;
                    seen = false;
                }
                ':' | ')' if enabled || seen => {
                    let mut set = String::new();
                    let mut unset = String::new();
                    for (flag, enabled) in "imsU".chars().zip(flags) {
                        match enabled {
                            Some(true) => set.push(flag),
                            Some(false) => unset.push(flag),
                            None => {}
                        }
                    }
                    if !unset.is_empty() {
                        set.push('-');
                        set.push_str(&unset);
                    }
                    return Ok(if set.is_empty() && character == ')' {
                        String::new()
                    } else {
                        format!("(?{set}{character}")
                    });
                }
                _ => return Err(format!("正则表达式不支持分组选项：{character}").into()),
            }
        }
    }

    fn escape(&mut self) -> Result<u32> {
        let character = self.next()?;
        Ok(match character {
            'a' => 7,
            'f' => 12,
            'n' => 10,
            'r' => 13,
            't' => 9,
            'v' => 11,
            '0'..='7' => {
                let digits: String = self
                    .text
                    .chars()
                    .take(2)
                    .take_while(|c| matches!(c, '0'..='7'))
                    .collect();
                if character != '0' && digits.is_empty() {
                    return Err("正则表达式不支持反向引用".into());
                }
                self.text = &self.text[digits.len()..];
                u32::from_str_radix(&format!("{character}{digits}"), 8)?
            }
            'x' => {
                let digits = if self.take("{") {
                    let (digits, rest) = self
                        .text
                        .split_once('}')
                        .ok_or("十六进制转义缺少右花括号")?;
                    self.text = rest;
                    digits.to_owned()
                } else {
                    format!("{}{}", self.next()?, self.next()?)
                };
                if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("正则表达式的十六进制转义不正确".into());
                }
                let digits = digits.trim_start_matches('0');
                let rune = if digits.is_empty() {
                    0
                } else {
                    u32::from_str_radix(digits, 16)?
                };
                if rune > char::MAX as u32 {
                    return Err("正则表达式的字符超出 Unicode 范围".into());
                }
                rune
            }
            c if c.is_ascii() && !c.is_ascii_alphanumeric() => c as u32,
            _ => return Err(format!("正则表达式不支持转义：\\{character}").into()),
        })
    }

    fn repetition(&mut self) -> Option<String> {
        let (counts, rest) = self.text.split_once('}')?;
        let (minimum, maximum) = counts.split_once(',').unwrap_or((counts, counts));
        let decimal = |s: &str| {
            !s.is_empty()
                && s.bytes().all(|c| c.is_ascii_digit())
                && (s.len() == 1 || !s.starts_with('0'))
        };
        if !decimal(minimum) || !maximum.is_empty() && !decimal(maximum) {
            return None;
        }
        self.text = rest;
        Some(format!("{{{counts}}}"))
    }

    fn take(&mut self, prefix: &str) -> bool {
        if let Some(rest) = self.text.strip_prefix(prefix) {
            self.text = rest;
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Result<char> {
        let character = self.text.chars().next().ok_or("正则表达式不完整")?;
        self.text = &self.text[character.len_utf8()..];
        Ok(character)
    }
}

fn canonical(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn range(low: u32, high: u32) -> String {
    let mut output = String::new();
    for (start, end) in [(low, high.min(0xd7ff)), (low.max(0xe000), high)] {
        if start <= end {
            write!(output, "\\x{{{start:X}}}").unwrap();
            if start != end {
                write!(output, "-\\x{{{end:X}}}").unwrap();
            }
        }
    }
    if output.is_empty() {
        "[a&&b]".to_owned()
    } else {
        format!("[{output}]")
    }
}
