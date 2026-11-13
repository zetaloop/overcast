use std::{
    borrow::Cow,
    collections::VecDeque,
    io::{IsTerminal, Write, stdout},
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    thread,
    time::{Duration, Instant},
};

use termina::{
    Event, PlatformTerminal, Terminal, WindowSize,
    escape::{
        csi::{Csi, Keyboard, KittyKeyboardFlags},
        osc::{Osc, Selection},
    },
    event::{KeyCode, KeyEvent, KeyEventKind, Modifiers},
    style::{AnsiColor, StyleExt, Stylized},
};
use unicode_width::UnicodeWidthStr;

use crate::{
    Result,
    input::{Editor, clip, visible, wrap},
    progress::{FRAME, Progress, Step},
};

type Line = Stylized<'static>;

pub struct Item {
    pub key: String,
    pub marker: &'static str,
    pub branch: Option<String>,
    pub label: Line,
    pub value: String,
    pub detail: String,
}

impl Item {
    pub fn new(key: impl Into<String>, label: Line) -> Self {
        Self {
            key: key.into(),
            marker: ">",
            branch: None,
            label,
            value: String::new(),
            detail: String::new(),
        }
    }
}

pub struct Menu<'a> {
    pub title: &'a str,
    pub heading: &'a str,
    pub items: &'a [Item],
    pub help: &'a str,
}

pub enum Action {
    Select,
    Back,
    Key(KeyEvent),
    Paste(String),
}

pub struct Screen {
    output: PlatformTerminal,
    rows: u16,
    alternate: Arc<AtomicBool>,
    pub(crate) arguments: VecDeque<String>,
    events: VecDeque<Event>,
    pub exiting: bool,
}

impl Screen {
    pub fn open(arguments: impl IntoIterator<Item = String>) -> Result<Self> {
        if !std::io::stdin().is_terminal() || !stdout().is_terminal() {
            return Err("Overcast 需要在终端中运行".into());
        }
        let mut screen = Self {
            output: PlatformTerminal::new()?,
            rows: 0,
            alternate: Arc::new(AtomicBool::new(true)),
            arguments: arguments.into_iter().collect(),
            events: VecDeque::new(),
            exiting: false,
        };
        screen.output.enter_raw_mode()?;
        let alternate = screen.alternate.clone();
        screen.output.set_panic_hook(move |output| {
            let _ = restore(output, alternate.swap(false, Ordering::Relaxed));
        });
        write!(
            screen.output,
            "\x1b[2J\x1b[3J\x1b[H\x1b[?1049h\x1b[?2004h\x1b[?25l{}",
            Csi::Keyboard(Keyboard::PushFlags(
                KittyKeyboardFlags::DISAMBIGUATE_ESCAPE_CODES
                    | KittyKeyboardFlags::REPORT_EVENT_TYPES
            )),
        )?;
        screen.output.flush()?;
        Ok(screen)
    }

    pub fn aliases(&mut self, aliases: &[(&str, &[&str])]) {
        if let Some((_, steps)) = aliases
            .iter()
            .find(|(name, _)| self.arguments.front().is_some_and(|value| value == name))
        {
            self.arguments.pop_front();
            for step in steps.iter().rev() {
                self.arguments.push_front((*step).to_owned());
            }
        }
    }

    pub(crate) fn dimensions(&self) -> Result<WindowSize> {
        Ok(self.output.get_dimensions()?)
    }

    pub(crate) fn draw(
        &mut self,
        title: &str,
        lines: &[Line],
        selected: &[(usize, Range<usize>)],
        cursor: Option<(usize, usize)>,
    ) -> Result<()> {
        let dimensions = self.dimensions()?;
        let (width, height) = (dimensions.cols, dimensions.rows);
        if width == 0 || height == 0 {
            return Ok(());
        }
        write!(
            self.output,
            "\x1b[?2026h\x1b[?25l\x1b[H{}\x1b[K",
            clip(&format!("==== Overcast [{title}] ===="), width as usize).bold(),
        )?;
        if height > 1 {
            write!(self.output, "\x1b[2;1H\x1b[K")?;
        }
        for (index, line) in lines
            .iter()
            .take(height.saturating_sub(2) as usize)
            .enumerate()
        {
            write!(self.output, "\x1b[{};1H", index + 3)?;
            let text = clip(&line.content, width as usize);
            let mut line = line.clone();
            if let Some((_, range)) = selected.iter().find(|(row, _)| *row == index) {
                let start = text.floor_char_boundary(range.start.min(text.len()));
                let end = text.floor_char_boundary(range.end.min(text.len()));
                line.content = Cow::Owned(format!(
                    "{}\x1b[7m{}\x1b[27m{}",
                    &text[..start],
                    &text[start..end],
                    &text[end..],
                ));
            } else {
                line.content = Cow::Owned(text);
            }
            write!(self.output, "{line}\x1b[m\x1b[K")?;
        }
        let end = (lines.len() + 2).min(height as usize);
        if end < height as usize {
            write!(self.output, "\x1b[{};1H\x1b[J", end + 1)?;
        }
        if let Some((column, row)) = cursor
            && row < height as usize
        {
            write!(
                self.output,
                "\x1b[{};{}H\x1b[?25h",
                row + 1,
                column.min(width as usize - 1) + 1,
            )?;
        }
        write!(self.output, "\x1b[?2026l")?;
        self.output.flush()?;
        self.rows = end as u16;
        Ok(())
    }

    pub(crate) fn event(&mut self, actions: bool) -> Result<Option<Event>> {
        let event = match self.events.pop_front() {
            Some(event) => event,
            None => self.output.read(|_| true)?,
        };
        if let Event::Key(key) = event {
            if key.kind == KeyEventKind::Release
                || key.kind == KeyEventKind::Repeat
                    && (key.code == KeyCode::Enter
                        || actions && matches!(key.code, KeyCode::Right | KeyCode::Char(' ')))
            {
                return Ok(None);
            }
            if actions && key.code == KeyCode::Char('c') && key.modifiers == Modifiers::CONTROL {
                self.exiting = true;
                return Ok(None);
            }
        }
        Ok(Some(event))
    }

    pub(crate) fn menu(
        &mut self,
        menu: &Menu<'_>,
        selected: usize,
        notice: &str,
        editor: Option<&mut Editor>,
    ) -> Result<()> {
        let dimensions = self.dimensions()?;
        let (width, height) = (dimensions.cols, dimensions.rows);
        let items = menu.items;
        let label_width = items
            .iter()
            .filter(|item| item.branch.is_none())
            .map(|item| visible(&item.label.content).width())
            .max()
            .unwrap_or_default();
        let destination_width = items
            .iter()
            .filter(|item| item.branch.is_some())
            .map(|item| visible(&item.value).width())
            .max()
            .unwrap_or_default()
            .min(width as usize / 3);
        let item = &items[selected];
        let editing = editor.is_some();
        let value =
            editor.map(|editor| editor.view((width as usize).saturating_sub(label_width + 9)));
        let mut footer = Vec::new();
        if !item.detail.is_empty() {
            footer.push(String::new().stylized());
            footer.extend(
                wrap(&item.detail, width as usize)
                    .into_iter()
                    .map(StyleExt::stylized),
            );
        }
        if !notice.is_empty() && notice != item.detail {
            footer.push(String::new().stylized());
            footer.extend(
                wrap(notice, width as usize)
                    .into_iter()
                    .map(|line| line.foreground(AnsiColor::BrightRed)),
            );
        }
        footer.push(String::new().stylized());
        let help = if editing {
            "回车键 确定\nEsc 取消\nCtrl+A 全选\nCtrl+C 复制 / Ctrl+X 剪切"
        } else {
            menu.help
        };
        footer.extend(help.lines().map(|line| line.to_owned().bold()));
        let mut lines = Vec::new();
        if !menu.heading.is_empty() {
            lines.push(menu.heading.to_owned().stylized());
            lines.push(String::new().stylized());
        }
        let offset = lines.len();
        let count = (height as usize)
            .saturating_sub(footer.len() + offset + 2)
            .max(1);
        let start = selected.saturating_sub(count - 1);
        lines.extend(
            items
                .iter()
                .enumerate()
                .skip(start)
                .take(count)
                .map(|(index, item)| {
                    let label = visible(&item.label.content);
                    let mut line = item.label.clone();
                    if let Some(branch) = &item.branch {
                        let available =
                            (width as usize).saturating_sub(branch.width() + destination_width + 5);
                        let label = clip(&label, available);
                        line.content = Cow::Owned(format!(
                            "  {branch}{label}{} → {}",
                            " ".repeat(available.saturating_sub(label.width())),
                            clip(&item.value, destination_width),
                        ));
                        return line;
                    }
                    line.content = Cow::Owned(format!(
                        "  {} {}{}    {}",
                        item.marker,
                        label,
                        " ".repeat(label_width - label.width()),
                        if index == selected {
                            value
                                .as_ref()
                                .map_or(item.value.as_str(), |(text, _, _)| text)
                        } else {
                            ""
                        },
                    ));
                    line
                }),
        );
        lines.extend(footer);
        let row = offset + selected - start;
        let label = visible(&item.label.content);
        let end = label.len() + label_width.saturating_sub(label.width()) + 7;
        let (highlight, cursor) = match value {
            Some((_, cursor, selection)) => (
                end + 1 + selection.start..end + 1 + selection.end,
                Some((label_width + 8 + cursor, row + 2)),
            ),
            None => (
                match &item.branch {
                    Some(branch) => 2 + branch.len()..lines[row].content.len(),
                    None => 0..end,
                },
                None,
            ),
        };
        self.draw(menu.title, &lines, &[(row, highlight)], cursor)
    }

    pub(crate) fn prompt<'a>(
        &mut self,
        title: &str,
        editor: &mut Editor,
        items: impl ExactSizeIterator<Item = &'a Item> + Clone,
        selected: Option<usize>,
        notice: &str,
        help: &str,
    ) -> Result<()> {
        let dimensions = self.dimensions()?;
        let width = dimensions.cols as usize;
        let (text, cursor, selection) = editor.view(width.saturating_sub(5));
        let mut lines = vec![format!("  -- {text}").stylized(), String::new().stylized()];
        let mut footer = Vec::new();
        if let Some(item) = selected.and_then(|index| items.clone().nth(index))
            && !item.detail.is_empty()
        {
            footer.push(String::new().stylized());
            footer.extend(
                wrap(&item.detail, width)
                    .into_iter()
                    .map(StyleExt::stylized),
            );
        }
        if !notice.is_empty() {
            footer.push(String::new().stylized());
            footer.extend(
                wrap(notice, width)
                    .into_iter()
                    .map(|line| line.foreground(AnsiColor::BrightRed)),
            );
        }
        footer.push(String::new().stylized());
        footer.extend(help.lines().map(|line| line.to_owned().bold()));
        let count = (dimensions.rows as usize)
            .saturating_sub(footer.len() + 4)
            .max(1);
        let start = selected.unwrap_or_default().saturating_sub(count - 1);
        let mut highlights = vec![(0, 5 + selection.start..5 + selection.end)];
        for (index, item) in items.enumerate().skip(start).take(count) {
            let mut line = item.label.clone();
            line.content = Cow::Owned(format!(
                "  {} {}    {}",
                item.marker,
                visible(&item.label.content),
                visible(&item.value),
            ));
            if selected == Some(index) {
                highlights.push((lines.len(), 0..line.content.len()));
            }
            lines.push(line);
        }
        lines.extend(footer);
        self.draw(title, &lines, &highlights, Some((5 + cursor, 2)))
    }

    pub(crate) fn search(
        &mut self,
        title: &str,
        items: &[Item],
        selected: usize,
    ) -> Result<Option<usize>> {
        if self.exiting {
            return Ok(None);
        }
        let mut notice = String::new();
        let mut editor = Editor::new(String::new());
        let mut selected = selected.min(items.len().saturating_sub(1));
        if let Some(argument) = self.arguments.pop_front() {
            match choice(items, selected, &argument) {
                Ok(index) => return Ok(Some(index)),
                Err(error) => {
                    notice = error;
                    editor = Editor::new(argument);
                    selected = 0;
                    self.arguments.clear();
                }
            }
        }
        let searchable: Vec<_> = items
            .iter()
            .map(|item| {
                format!("{} {} {}", item.key, item.label.content, item.value).to_lowercase()
            })
            .collect();
        while !self.exiting {
            let query = editor.text().to_lowercase();
            let terms: Vec<_> = query.split_whitespace().collect();
            let matches: Vec<_> = searchable
                .iter()
                .enumerate()
                .filter(|(_, text)| terms.iter().all(|term| text.contains(term)))
                .map(|(index, _)| index)
                .collect();
            selected = selected.min(matches.len().saturating_sub(1));
            self.prompt(
                title,
                &mut editor,
                matches.iter().map(|index| &items[*index]),
                (!matches.is_empty()).then_some(selected),
                &notice,
                "输入文字 搜索\n↑↓ 选择\n回车键 确定\nEsc 返回",
            )?;
            let Some(event) = self.event(false)? else {
                continue;
            };
            if let Event::Key(key) = event {
                match key.code {
                    KeyCode::Escape => return Ok(None),
                    KeyCode::Enter if !matches.is_empty() => return Ok(Some(matches[selected])),
                    KeyCode::Up if !matches.is_empty() => {
                        selected = (selected + matches.len() - 1) % matches.len();
                        continue;
                    }
                    KeyCode::Down if !matches.is_empty() => {
                        selected = (selected + 1) % matches.len();
                        continue;
                    }
                    KeyCode::PageUp => {
                        selected = 0;
                        continue;
                    }
                    KeyCode::PageDown => {
                        selected = matches.len().saturating_sub(1);
                        continue;
                    }
                    _ => {}
                }
            }
            let previous = editor.text().to_owned();
            self.edit(&mut editor, event)?;
            if editor.text() != previous {
                selected = 0;
                notice.clear();
            }
        }
        Ok(None)
    }

    pub fn select(
        &mut self,
        menu: &Menu<'_>,
        selected: &mut usize,
        notice: &str,
    ) -> Result<Action> {
        if self.exiting {
            return Ok(Action::Back);
        }
        let items = menu.items;
        if items.is_empty() {
            return Err("菜单中没有可选择的项目".into());
        }
        *selected = (*selected).min(items.len() - 1);
        let mut notice = notice.to_owned();
        if !notice.is_empty() {
            self.arguments.clear();
        }
        if let Some(argument) = self.arguments.pop_front() {
            match choice(items, *selected, &argument) {
                Ok(index) => {
                    *selected = index;
                    return Ok(Action::Select);
                }
                Err(error) => {
                    notice = error;
                    self.arguments.clear();
                }
            }
        }
        while !self.exiting {
            self.menu(menu, *selected, &notice, None)?;
            let key = match self.event(true)? {
                Some(Event::Key(key)) => key,
                Some(Event::Paste(text)) => return Ok(Action::Paste(text)),
                _ => continue,
            };
            if key
                .modifiers
                .intersects(Modifiers::CONTROL | Modifiers::ALT)
            {
                return Ok(Action::Key(key));
            }
            match key.code {
                KeyCode::Up => *selected = (*selected + items.len() - 1) % items.len(),
                KeyCode::Down => *selected = (*selected + 1) % items.len(),
                KeyCode::Home | KeyCode::PageUp => *selected = 0,
                KeyCode::End | KeyCode::PageDown => *selected = items.len() - 1,
                KeyCode::Enter | KeyCode::Right | KeyCode::Char(' ') => return Ok(Action::Select),
                KeyCode::Escape | KeyCode::Left => return Ok(Action::Back),
                _ => return Ok(Action::Key(key)),
            }
        }
        Ok(Action::Back)
    }

    pub fn input<T>(
        &mut self,
        menu: &Menu<'_>,
        selected: usize,
        value: &str,
        parse: impl Fn(&str, &mut Self) -> Result<T>,
    ) -> Result<Option<T>> {
        if self.exiting {
            return Ok(None);
        }
        let mut editor = Editor::new(value.to_owned());
        let mut notice = String::new();
        if let Some(argument) = self.arguments.pop_front() {
            if argument != "-" {
                editor = Editor::new(argument);
            }
            match parse(editor.text(), self) {
                Ok(value) => return Ok(Some(value)),
                Err(error) => {
                    notice = error.to_string();
                    self.arguments.clear();
                }
            }
        }
        while !self.exiting {
            self.menu(menu, selected, &notice, Some(&mut editor))?;
            match self.event(false)? {
                Some(Event::Key(key)) if key.code == KeyCode::Enter => {
                    match parse(editor.text(), self) {
                        Ok(value) => return Ok(Some(value)),
                        Err(error) => notice = error.to_string(),
                    }
                }
                Some(Event::Key(key)) if key.code == KeyCode::Escape => return Ok(None),
                Some(event) => self.edit(&mut editor, event)?,
                _ => {}
            }
        }
        Ok(None)
    }

    pub(crate) fn edit(&mut self, editor: &mut Editor, event: Event) -> Result<()> {
        match event {
            Event::Key(key)
                if matches!(key.code, KeyCode::Char('c' | 'x'))
                    && key.kind == KeyEventKind::Press
                    && key
                        .modifiers
                        .intersects(Modifiers::CONTROL | Modifiers::SUPER)
                    && !key.modifiers.contains(Modifiers::ALT) =>
            {
                if !editor.selected().is_empty() {
                    self.copy(editor.selected())?;
                    if key.code == KeyCode::Char('x') {
                        editor.insert("");
                    }
                }
            }
            Event::Key(key) => editor.key(key),
            Event::Paste(text) => editor.insert(&text),
            _ => {}
        }
        Ok(())
    }

    pub fn copy(&mut self, text: &str) -> Result<()> {
        write!(
            self.output,
            "{}",
            Osc::SetSelection(Selection::CLIPBOARD, text)
        )?;
        self.output.flush()?;
        Ok(())
    }

    pub fn work<T: Send>(
        &mut self,
        title: &str,
        detail: &str,
        operation: impl FnOnce(&Progress) -> Result<T> + Send,
    ) -> Result<T> {
        let progress = Progress::default();
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::scope(|scope| {
            let worker_progress = progress.clone();
            scope.spawn(move || {
                let _ = sender.send(operation(&worker_progress));
            });
            let result: Result<T> = (|| {
                let started = Instant::now();
                let mut deadline = started + Duration::from_millis(150);
                let mut cancelled = false;
                loop {
                    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    {
                        Ok(result) => return result,
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => {
                            return Err("处理线程已中断".into());
                        }
                    }
                    let dimensions = self.dimensions()?;
                    let (width, height) = (dimensions.cols, dimensions.rows);
                    let steps = progress.steps();
                    let mut lines: Vec<Line> = wrap(detail, width as usize)
                        .into_iter()
                        .map(StyleExt::stylized)
                        .collect();
                    lines.push(String::new().stylized());
                    let records = progress.records();
                    let mut current = Vec::new();
                    for (step, text) in steps.iter().filter_map(|step| {
                        let text = step.text();
                        (!text.finished).then_some((step, text))
                    }) {
                        let name = step.group.as_deref().unwrap_or(&step.name);
                        step.request();
                        let mut detail = text.detail.lines();
                        let heading = if step.total != 0 {
                            format!(
                                "{name}：{}/{} {}；",
                                step.completed(),
                                step.total,
                                step.unit
                            )
                        } else {
                            format!("{name}：")
                        };
                        let size = (width as usize).saturating_sub(heading.width());
                        current.push(
                            clip(
                                &format!("{heading}{}", bar(step, size, started.elapsed())),
                                width as usize,
                            )
                            .stylized(),
                        );
                        if let Some(line) = detail.next() {
                            current.push(clip(&format!("  {line}"), width as usize).stylized());
                        }
                        let detail = detail.collect::<Vec<_>>().join("；");
                        if !detail.is_empty() {
                            current.push(clip(&format!("  {detail}"), width as usize).stylized());
                        }
                    }
                    current.truncate((height as usize).saturating_sub(lines.len() + 4));
                    let available =
                        (height as usize).saturating_sub(lines.len() + current.len() + 4);
                    let logs = records.iter().flat_map(|record| {
                        let name = record.group.as_deref().unwrap_or(&record.name);
                        record.detail.lines().flat_map(move |line| {
                            wrap(&format!("{name}：{line}"), width as usize)
                                .into_iter()
                                .map(StyleExt::stylized)
                        })
                    });
                    let logs: Vec<_> = logs.rev().take(available).collect();
                    lines.extend(logs.into_iter().rev());
                    lines.extend(current);
                    lines.push(String::new().stylized());
                    lines.push(
                        if cancelled {
                            "正在取消…"
                        } else {
                            "Esc 取消"
                        }
                        .to_owned()
                        .bold(),
                    );
                    self.draw(title, &lines, &[], None)?;
                    if self.output.poll(|_| true, Some(Duration::ZERO))? {
                        let event = self.output.read(|_| true)?;
                        if let Event::Key(key) = event
                            && key.kind != KeyEventKind::Release
                            && (key.code == KeyCode::Escape
                                || key.code == KeyCode::Char('c')
                                    && key.modifiers == Modifiers::CONTROL)
                        {
                            cancelled = true;
                            self.exiting |= key.code == KeyCode::Char('c');
                            progress.cancel();
                        } else {
                            self.events.push_back(event);
                        }
                    }
                    deadline += FRAME;
                    if deadline < Instant::now() {
                        deadline = Instant::now();
                    }
                }
            })();
            if result.is_err() {
                progress.cancel();
            }
            result
        })
    }

    pub fn about(&mut self) -> Result<()> {
        self.draw("关于", &[], &[], None)?;
        write!(self.output, "\x1b[3;1H")?;
        let body = format!(
            "\x1b[1m   Overcast v{}\n\x1b[0m   By zetaloop\n\n[",
            env!("CARGO_PKG_VERSION")
        );
        let mut bytes = Vec::new();
        for (index, byte) in body.bytes().chain(Some(0)).enumerate() {
            bytes.push(byte);
            if let Ok(text) = std::str::from_utf8(&bytes) {
                self.output
                    .write_all(if text == "\n" { b"\r\n" } else { &bytes })?;
                self.output.flush()?;
                bytes.clear();
            }
            sleep(index as u32 % 2);
        }
        let repository = "github.com/zetaloop/overcast";
        for (index, byte) in repository.bytes().chain(Some(0)).enumerate() {
            let frame = format!(
                "\x1b[34;1m\x1b[4m\x1b]8;;https://{repository}\x1b\\{}\x1b]8;;\x1b\\\x1b[0m]\x1b[1D",
                char::from(byte)
            );
            self.output.write_all(frame.as_bytes())?;
            self.output.flush()?;
            sleep(index as u32 % 2);
        }
        write!(self.output, "]\r\n\r\n\x1b[7m  > 返回   \x1b[m")?;
        self.output.flush()?;
        self.rows = 8;
        if self.arguments.pop_front().is_none() {
            while !self.exiting {
                if matches!(self.event(true)?, Some(Event::Key(_))) {
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        let heading = "==== Overcast [退出] ====";
        write!(self.output, "\x1b[H{}\x1b[K", heading.bold())?;
        self.output.flush()?;
        let start = Instant::now();
        for row in (2..self.rows).rev() {
            let remaining = f64::from(row - 2) / f64::from(self.rows - 2);
            let deadline = start + Duration::from_millis(350).mul_f64(1.0 - remaining.sqrt());
            sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u32,
            );
            write!(self.output, "\x1b[{};1H\x1b[2K", row + 1)?;
            self.output.flush()?;
        }
        let banner = format!("  Overcast v{}  ", env!("CARGO_PKG_VERSION"));
        write!(self.output, "\x1b[3;2H\x1b[7m")?;
        let mut written = 0;
        for tick in 0..39 {
            let visible = (tick + 1) * banner.len() / 39;
            self.output
                .write_all(&banner.as_bytes()[written..visible])?;
            self.output.flush()?;
            written = visible;
            sleep(tick as u32 % 2);
        }
        sleep(250);
        write!(
            self.output,
            "\x1b[m\x1b[?2026h{}\x1b[?1049l",
            Csi::Keyboard(Keyboard::PopFlags(1)),
        )?;
        self.alternate.store(false, Ordering::Relaxed);
        write!(
            self.output,
            "{}\r\n\r\n \x1b[7m{banner}\x1b[m\r\n\x1b[?2026l",
            heading.bold()
        )?;
        self.output.flush()?;
        Ok(())
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = restore(
            &mut self.output,
            self.alternate.swap(false, Ordering::Relaxed),
        );
    }
}

fn sleep(milliseconds: u32) {
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Threading::Sleep(milliseconds)
    };
    #[cfg(not(windows))]
    thread::sleep(Duration::from_millis(milliseconds as u64));
}

fn restore(output: &mut impl Write, alternate: bool) -> std::io::Result<()> {
    write!(output, "\x1b[?2026l\x1b[m\x1b[?25h\x1b[?2004l")?;
    if alternate {
        write!(
            output,
            "{}\x1b[?1049l",
            Csi::Keyboard(Keyboard::PopFlags(1))
        )?;
    }
    output.flush()
}

pub(crate) fn choice(
    items: &[Item],
    selected: usize,
    argument: &str,
) -> std::result::Result<usize, String> {
    if argument == "-" {
        return items
            .get(selected)
            .map(|_| selected)
            .ok_or_else(|| "没有可选择的项目".to_owned());
    }
    let mut matches = items
        .iter()
        .enumerate()
        .filter(|(_, item)| item.key == argument || item.label.content == argument);
    let Some((index, _)) = matches.next() else {
        return Err(format!("找不到菜单项：{argument}"));
    };
    if matches.next().is_some() {
        return Err(format!("名称对应多个菜单项：{argument}"));
    }
    Ok(index)
}

fn bar(step: &Step, width: usize, elapsed: Duration) -> String {
    if step.total == 0 {
        let mut cells = vec![' '; width];
        if !cells.is_empty() {
            cells[..width.div_ceil(4)].fill('█');
            cells.rotate_right((elapsed.as_millis() / 50) as usize % width);
        }
        return cells.into_iter().collect();
    }
    let fraction = step.completed() as f64 / step.total as f64;
    let cells = width.saturating_sub(8);
    let units = (fraction * cells as f64 * 8.0) as usize;
    let whole = units / 8;
    let partial = units % 8;
    let mut result = "█".repeat(whole);
    if partial != 0 {
        result.push([' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'][partial]);
    }
    result.push_str(&" ".repeat(cells.saturating_sub(whole + usize::from(partial != 0))));
    format!("{result} {:5.1}%", fraction * 100.0)
}
