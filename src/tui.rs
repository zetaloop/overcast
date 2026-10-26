use std::{
    collections::VecDeque,
    io::{IsTerminal, Stdout, Write, stdout},
    ops::Range,
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind,
        KeyModifiers,
    },
    execute, queue,
    style::{Attribute, Print, SetAttribute, StyledContent, Stylize, style},
    terminal::{
        self, BeginSynchronizedUpdate, Clear, ClearType, EndSynchronizedUpdate,
        EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use unicode_width::UnicodeWidthStr;

use crate::{
    Result,
    input::{Editor, clip, visible, wrap},
    progress::{FRAME, Progress, Step},
};

type Line = StyledContent<String>;

pub struct Item {
    pub key: String,
    pub label: Line,
    pub value: String,
    pub detail: String,
}

impl Item {
    pub fn new(key: impl Into<String>, label: StyledContent<&str>) -> Self {
        Self {
            key: key.into(),
            label: label.style().apply((*label.content()).to_owned()),
            value: String::new(),
            detail: String::new(),
        }
    }
}

pub struct Screen {
    output: Stdout,
    arguments: VecDeque<String>,
    events: VecDeque<Event>,
    pub exiting: bool,
    #[cfg(windows)]
    pressed: std::collections::HashSet<KeyCode>,
}

impl Screen {
    pub fn open(arguments: impl IntoIterator<Item = String>) -> Result<Self> {
        if !std::io::stdin().is_terminal() || !stdout().is_terminal() {
            return Err("Overcast 需要在终端中运行".into());
        }
        let mut screen = Self {
            output: stdout(),
            arguments: arguments.into_iter().collect(),
            events: VecDeque::new(),
            exiting: false,
            #[cfg(windows)]
            pressed: Default::default(),
        };
        terminal::enable_raw_mode()?;
        execute!(
            screen.output,
            EnterAlternateScreen,
            EnableBracketedPaste,
            Hide,
            Clear(ClearType::All),
            MoveTo(0, 0),
        )?;
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            hook(info);
        }));
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

    fn draw(
        &mut self,
        title: &str,
        lines: &[Line],
        selected: Option<(usize, Range<usize>)>,
        cursor: Option<(usize, usize)>,
    ) -> Result<()> {
        let (width, height) = terminal::size()?;
        if width == 0 || height == 0 {
            return Ok(());
        }
        queue!(
            self.output,
            BeginSynchronizedUpdate,
            Hide,
            MoveTo(0, 0),
            SetAttribute(Attribute::Bold),
            Print(clip(
                &format!("==== Overcast [{title}] ===="),
                width as usize
            )),
            SetAttribute(Attribute::Reset),
            Clear(ClearType::UntilNewLine),
        )?;
        if height > 1 {
            queue!(self.output, MoveTo(0, 1), Clear(ClearType::UntilNewLine))?;
        }
        for (index, line) in lines
            .iter()
            .take(height.saturating_sub(2) as usize)
            .enumerate()
        {
            queue!(self.output, MoveTo(0, index as u16 + 2))?;
            let text = clip(line.content(), width as usize);
            if let Some((_, range)) = selected.as_ref().filter(|(row, _)| *row == index) {
                let start = text.floor_char_boundary(range.start.min(text.len()));
                let end = text.floor_char_boundary(range.end.min(text.len()));
                let mut appearance = *line.style();
                appearance.attributes.set(Attribute::Reverse);
                queue!(
                    self.output,
                    Print(line.style().apply(&text[..start])),
                    Print(appearance.apply(&text[start..end])),
                    Print(line.style().apply(&text[end..]))
                )?;
            } else {
                queue!(self.output, Print(line.style().apply(text)))?;
            }
            queue!(
                self.output,
                SetAttribute(Attribute::Reset),
                Clear(ClearType::UntilNewLine),
            )?;
        }
        let end = (lines.len() + 2).min(height as usize);
        if end < height as usize {
            queue!(
                self.output,
                MoveTo(0, end as u16),
                Clear(ClearType::FromCursorDown)
            )?;
        }
        if let Some((column, row)) = cursor
            && row < height as usize
        {
            queue!(
                self.output,
                MoveTo(column.min(width as usize - 1) as u16, row as u16),
                Show
            )?;
        }
        queue!(self.output, EndSynchronizedUpdate)?;
        self.output.flush()?;
        Ok(())
    }

    fn event(&mut self, actions: bool) -> Result<Option<Event>> {
        let event = match self.events.pop_front() {
            Some(event) => event,
            None => event::read()?,
        };
        if let Event::Key(key) = event {
            #[cfg(windows)]
            {
                if key.kind == KeyEventKind::Release {
                    self.pressed.remove(&key.code);
                } else if self.pressed.contains(&key.code) {
                    return Ok(None);
                } else if key.code == KeyCode::Enter
                    || actions && matches!(key.code, KeyCode::Right | KeyCode::Char(' '))
                {
                    self.pressed.insert(key.code);
                }
            }
            #[cfg(not(windows))]
            let _ = actions;
            if key.kind == KeyEventKind::Release {
                return Ok(None);
            }
            if key.code == KeyCode::Char('c') && key.modifiers == KeyModifiers::CONTROL {
                self.exiting = true;
                return Ok(None);
            }
        }
        Ok(Some(event))
    }

    pub fn select(
        &mut self,
        title: &str,
        heading: &str,
        items: &[Item],
        selected: &mut usize,
        notice: &str,
    ) -> Result<bool> {
        if self.exiting {
            return Ok(false);
        }
        if items.is_empty() {
            return Err("菜单中没有可选择的项目".into());
        }
        *selected = (*selected).min(items.len() - 1);
        let mut notice = notice.to_owned();
        if notice.is_empty()
            && let Some(argument) = self.arguments.pop_front()
        {
            match choice(items, *selected, &argument) {
                Ok(index) => {
                    *selected = index;
                    return Ok(true);
                }
                Err(error) => notice = error,
            }
        }
        let label_width = items
            .iter()
            .map(|item| visible(item.label.content()).width())
            .max()
            .unwrap_or_default();
        while !self.exiting {
            let (width, height) = terminal::size()?;
            let item = &items[*selected];
            let mut footer = Vec::new();
            if !notice.is_empty() {
                footer.push(style(String::new()));
                footer.extend(
                    wrap(&notice, width as usize)
                        .into_iter()
                        .map(|line| line.red()),
                );
            }
            if !item.detail.is_empty() && item.detail != notice {
                footer.push(style(String::new()));
                footer.extend(wrap(&item.detail, width as usize).into_iter().map(style));
            }
            footer.push(style(String::new()));
            footer.push("方向键 选择　回车键 确定　Esc 返回".to_owned().bold());
            let mut lines = Vec::new();
            if !heading.is_empty() {
                lines.extend(wrap(heading, width as usize).into_iter().map(style));
                lines.push(style(String::new()));
            }
            let offset = lines.len();
            let count = (height as usize)
                .saturating_sub(footer.len() + offset + 2)
                .max(1);
            let start = selected.saturating_sub(count - 1);
            let label = visible(item.label.content());
            let highlight = label.len() + label_width - label.width() + 7;
            lines.extend(
                items
                    .iter()
                    .enumerate()
                    .skip(start)
                    .take(count)
                    .map(|(index, item)| {
                        let label = visible(item.label.content());
                        item.label.style().apply(format!(
                            "  > {}{}    {}",
                            label,
                            " ".repeat(label_width - label.width()),
                            if index == *selected { &item.value } else { "" }
                        ))
                    }),
            );
            lines.extend(footer);
            self.draw(
                title,
                &lines,
                Some((offset + *selected - start, 0..highlight)),
                None,
            )?;
            let Some(Event::Key(key)) = self.event(true)? else {
                continue;
            };
            match key.code {
                KeyCode::Up => *selected = (*selected + items.len() - 1) % items.len(),
                KeyCode::Down => *selected = (*selected + 1) % items.len(),
                KeyCode::Home => *selected = 0,
                KeyCode::End => *selected = items.len() - 1,
                KeyCode::PageUp => *selected = selected.saturating_sub(count),
                KeyCode::PageDown => *selected = (*selected + count).min(items.len() - 1),
                KeyCode::Enter | KeyCode::Right | KeyCode::Char(' ') => return Ok(true),
                KeyCode::Esc | KeyCode::Left => return Ok(false),
                _ => {}
            }
        }
        Ok(false)
    }

    pub fn input(
        &mut self,
        title: &str,
        detail: &str,
        value: &str,
        validate: impl Fn(&str) -> Result<()>,
    ) -> Result<Option<String>> {
        if self.exiting {
            return Ok(None);
        }
        let mut editor = Editor::new(value.to_owned());
        let mut notice = String::new();
        if let Some(argument) = self.arguments.pop_front() {
            if argument != "-" {
                editor = Editor::new(argument);
            }
            match validate(editor.text()) {
                Ok(()) => return Ok(Some(editor.into_text())),
                Err(error) => notice = error.to_string(),
            }
        }
        while !self.exiting {
            let (width, _) = terminal::size()?;
            let (text, cursor, selection) = editor.view(width.saturating_sub(5) as usize);
            let mut lines = vec![style(format!(" -- {text}"))];
            if !notice.is_empty() {
                lines.push(style(String::new()));
                lines.extend(
                    wrap(&notice, width as usize)
                        .into_iter()
                        .map(|line| line.red()),
                );
            }
            if !detail.is_empty() {
                lines.push(style(String::new()));
                lines.extend(wrap(detail, width as usize).into_iter().map(style));
            }
            lines.push(style(String::new()));
            lines.push("回车键 确定　Esc 返回　Ctrl+A 全选".to_owned().bold());
            self.draw(
                title,
                &lines,
                Some((0, selection.start + 4..selection.end + 4)),
                Some((cursor + 4, 2)),
            )?;
            match self.event(false)? {
                Some(Event::Key(key)) => match key.code {
                    KeyCode::Enter => match validate(editor.text()) {
                        Ok(()) => return Ok(Some(editor.into_text())),
                        Err(error) => notice = error.to_string(),
                    },
                    KeyCode::Esc => return Ok(None),
                    _ => editor.key(key),
                },
                Some(Event::Paste(text)) => editor.insert(&text),
                _ => {}
            }
        }
        Ok(None)
    }

    pub fn work<T: Send>(
        &mut self,
        title: &str,
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
                let mut cancelled = false;
                loop {
                    match receiver.recv_timeout(FRAME) {
                        Ok(result) => return result,
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => {
                            return Err("处理线程已中断".into());
                        }
                    }
                    let (width, height) = terminal::size()?;
                    let steps = progress.steps();
                    let mut lines = Vec::new();
                    let mut current = Vec::new();
                    for step in &steps {
                        let text = step.text();
                        if text.finished {
                            lines.extend(
                                wrap(&format!("{}：{}", step.name, text.detail), width as usize)
                                    .into_iter()
                                    .map(style),
                            );
                        } else {
                            let heading = if step.total == 0 {
                                format!("{}：", step.name)
                            } else {
                                format!(
                                    "{}：{}/{} {}；",
                                    step.name,
                                    step.completed(),
                                    step.total,
                                    step.unit
                                )
                            };
                            current.push(style(format!(
                                "{}{}",
                                heading,
                                bar(
                                    step,
                                    (width as usize).saturating_sub(visible(&heading).width()),
                                    started.elapsed()
                                )
                            )));
                            current
                                .extend(wrap(&text.detail, width as usize).into_iter().map(style));
                        }
                    }
                    let count = (height as usize).saturating_sub(current.len() + 4);
                    let skip = lines.len().saturating_sub(count);
                    let mut lines: Vec<_> = lines.into_iter().skip(skip).collect();
                    lines.extend(current);
                    lines.push(style(String::new()));
                    lines.push(
                        if cancelled {
                            "正在取消…"
                        } else {
                            "Esc 取消"
                        }
                        .to_owned()
                        .bold(),
                    );
                    self.draw(title, &lines, None, None)?;
                    if event::poll(Duration::ZERO)? {
                        let event = event::read()?;
                        if let Event::Key(key) = event
                            && key.kind != KeyEventKind::Release
                            && (key.code == KeyCode::Esc
                                || key.code == KeyCode::Char('c')
                                    && key.modifiers == KeyModifiers::CONTROL)
                        {
                            cancelled = true;
                            self.exiting |= key.code == KeyCode::Char('c');
                            progress.cancel();
                        } else {
                            self.events.push_back(event);
                        }
                    }
                }
            })();
            if result.is_err() {
                progress.cancel();
            }
            result
        })
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        restore();
    }
}

fn restore() {
    let _ = execute!(
        stdout(),
        EndSynchronizedUpdate,
        SetAttribute(Attribute::Reset),
        Show,
        DisableBracketedPaste,
        LeaveAlternateScreen
    );
    let _ = terminal::disable_raw_mode();
}

fn choice(items: &[Item], selected: usize, argument: &str) -> std::result::Result<usize, String> {
    if argument == "-" {
        return Ok(selected);
    }
    let mut matches = items
        .iter()
        .enumerate()
        .filter(|(_, item)| item.key == argument || item.label.content() == argument);
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
    let fraction = (step.completed() as f64 / step.total as f64).min(1.0);
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
