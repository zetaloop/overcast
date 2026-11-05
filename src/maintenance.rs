use std::{rc::Rc, time::Duration};

use serde::{Deserialize, Serialize};
use termina::style::StyleExt;

use crate::{
    Result,
    component::{self, Component},
    config::Store,
    form::{self, choices, fields},
    geodata::Catalog,
    progress::Progress,
    resource::{self, Resources},
    tui::{Action, Item, Menu, Screen},
};

#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Schedule {
    pub enabled: bool,
    pub mode: Mode,
    pub calendar: Calendar,
    pub interval: String,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: Mode::default(),
            calendar: Calendar::default(),
            interval: "1day".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Calendar,
    Interval,
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Calendar {
    pub time: String,
    pub weekdays: Vec<Day>,
}

impl Default for Calendar {
    fn default() -> Self {
        Self {
            time: "04:00".to_owned(),
            weekdays: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Day {
    #[default]
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl Schedule {
    pub fn next(&self) -> Result<Option<Duration>> {
        if !self.enabled {
            return Ok(None);
        }
        match self.mode {
            Mode::Calendar => {
                let (hour, minute) = self
                    .calendar
                    .time
                    .trim()
                    .split_once(':')
                    .ok_or("维护时间使用 HH:mm 格式")?;
                let hour: i8 = hour.parse().map_err(|_| "维护时间的小时格式不正确")?;
                let minute: i8 = minute.parse().map_err(|_| "维护时间的分钟格式不正确")?;
                let time = jiff::civil::Time::new(hour, minute, 0, 0)
                    .map_err(|_| "维护时间使用 00:00 至 23:59")?;
                let now = jiff::Zoned::now();
                let mut date = now.date();
                for _ in 0..8 {
                    let at = date.to_datetime(time).to_zoned(now.time_zone().clone())?;
                    if at > now
                        && (self.calendar.weekdays.is_empty()
                            || self.calendar.weekdays.contains(&Day::from(at.weekday())))
                    {
                        return Ok(Some(now.duration_until(&at).unsigned_abs()));
                    }
                    date = date.tomorrow()?;
                }
                unreachable!("calendar schedule within a week")
            }
            Mode::Interval => {
                let interval = humantime::parse_duration(&self.interval)
                    .map_err(|error| format!("维护间隔格式不正确：{error}"))?;
                if interval.is_zero() {
                    return Err("维护间隔需要大于零".into());
                }
                Ok(Some(interval))
            }
        }
    }
}

impl From<jiff::civil::Weekday> for Day {
    fn from(day: jiff::civil::Weekday) -> Self {
        use jiff::civil::Weekday;
        match day {
            Weekday::Monday => Self::Monday,
            Weekday::Tuesday => Self::Tuesday,
            Weekday::Wednesday => Self::Wednesday,
            Weekday::Thursday => Self::Thursday,
            Weekday::Friday => Self::Friday,
            Weekday::Saturday => Self::Saturday,
            Weekday::Sunday => Self::Sunday,
        }
    }
}

impl form::Form for Schedule {
    fn fields<'a>(&'a mut self, defaults: Self, apply: form::Apply<'a, Self>) -> form::Fields<'a> {
        let source = Rc::new(self.clone());
        let mut fields = vec![
            form::field(
                "enabled",
                "启用",
                &mut self.enabled,
                defaults.enabled,
                form::map(source.clone(), apply.clone(), |value, enabled| {
                    value.enabled = enabled
                }),
            ),
            form::field(
                "mode",
                "安排方式",
                &mut self.mode,
                defaults.mode,
                form::map(source.clone(), apply.clone(), |value, mode| {
                    value.mode = mode
                }),
            ),
        ];
        match source.mode {
            Mode::Calendar => fields.push(form::field(
                "calendar",
                "日历安排",
                &mut self.calendar,
                defaults.calendar,
                form::map(source, apply, |value, calendar| value.calendar = calendar),
            )),
            Mode::Interval => fields.push(form::field(
                "interval",
                "间隔",
                &mut self.interval,
                defaults.interval,
                form::map(source, apply, |value, interval| value.interval = interval),
            )),
        }
        fields
    }
}

fields!(Calendar {
    time: "时间",
    weekdays: "星期筛选",
});

choices!(Mode {
    Calendar: "calendar" => "日历安排",
    Interval: "interval" => "固定间隔",
});

choices!(Day {
    Monday: "monday" => "周一",
    Tuesday: "tuesday" => "周二",
    Wednesday: "wednesday" => "周三",
    Thursday: "thursday" => "周四",
    Friday: "friday" => "周五",
    Saturday: "saturday" => "周六",
    Sunday: "sunday" => "周日",
});

pub fn update(store: &Store, progress: &Progress) -> Result<()> {
    let config = store.load()?;
    let mut prepared = Resources::load(store)?;
    component::update(store, &config, &mut prepared, progress)?;
    if prepared.geodata.is_some() {
        prepared.geodata = Some(Catalog::update(store, progress)?.release);
    }
    store.update(progress, |_, resources| {
        resources.components.extend(prepared.components);
        if let Some(release) = prepared.geodata {
            resources.geodata = Some(release);
        }
        Ok(())
    })
}

pub fn rules(store: &Store, progress: &Progress) -> Result<()> {
    let catalog = Catalog::update(store, progress)?;
    store.update(progress, |_, resources| {
        resources.geodata = Some(catalog.release);
        Ok(())
    })
}

pub fn run(screen: &mut Screen, store: &Store) -> Result<()> {
    let client = resource::client();
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let config = store.load()?;
        let resources = Resources::load(store)?;
        let mut items: Vec<_> = Component::ALL
            .iter()
            .map(|component| {
                let mut item = Item::new(component.key(), component.name().stylized());
                item.value = resources.components.get(component).map_or_else(
                    || "未安装".to_owned(),
                    |installed| installed.version.clone(),
                );
                item
            })
            .collect();
        let mut running = Item::new("running", "运行服务".stylized());
        running.marker = if config.running { "■" } else { "□" };
        let mut schedule = Item::new("schedule", "定时维护".stylized());
        schedule.value = if config.maintenance.enabled {
            "开启"
        } else {
            "关闭"
        }
        .to_owned();
        items.extend([
            running,
            Item::new("rules", "更新规则数据".stylized()),
            Item::new("update", "更新全部".stylized()),
            schedule,
            Item::new("back", "返回".stylized()),
        ]);
        let menu = Menu {
            title: "维护",
            heading: "",
            items: &items,
            help: "方向键 选择\n回车键 确定\nEsc 返回",
        };
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(()),
            Action::Select => {}
            _ => continue,
        }
        let result = if let Some(component) = Component::ALL.get(selected) {
            component::edit(screen, store, &client, *component)
        } else {
            match items[selected].key.as_str() {
                "running" => screen.work(
                    if config.running {
                        "停止服务"
                    } else {
                        "启动服务"
                    },
                    "",
                    |progress| {
                        store.update(progress, |config, _| {
                            config.running = !config.running;
                            Ok(())
                        })
                    },
                ),
                "rules" => screen.work("更新规则数据", "", |progress| rules(store, progress)),
                "update" => screen.work("更新资源", "", |progress| update(store, progress)),
                "schedule" => form::edit(
                    screen,
                    "定时维护",
                    &mut config.maintenance.clone(),
                    Rc::new(|settings: &Schedule, screen| {
                        screen.work("更新维护日程", "", |progress| {
                            store.update(progress, |config, _| {
                                config.maintenance = settings.clone();
                                Ok(())
                            })
                        })
                    }),
                    false,
                )
                .map(|_| ()),
                _ => return Ok(()),
            }
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}
