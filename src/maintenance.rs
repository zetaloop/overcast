use crate::language::{message, text as tr};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use termina::style::StyleExt;

use crate::{
    Result,
    component::{self, Component},
    config::Store,
    form::{self, Value, choices},
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
    pub weekdays: Weekdays,
}

impl Default for Calendar {
    fn default() -> Self {
        Self {
            time: "04:00".to_owned(),
            weekdays: Weekdays::default(),
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

#[derive(Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Weekdays(Vec<Day>);

impl Schedule {
    pub fn next(&self) -> Result<Option<Duration>> {
        if !self.enabled {
            return Ok(None);
        }
        match self.mode {
            Mode::Calendar => {
                let (hour, minute) = self.calendar.time.trim().split_once(':').ok_or(tr(
                    "Enter the maintenance time as HH:mm",
                    "维护时间使用 HH:mm 格式",
                ))?;
                let hour: i8 = hour
                    .parse()
                    .map_err(|_| tr("Invalid maintenance hour", "维护时间的小时格式不正确"))?;
                let minute: i8 = minute
                    .parse()
                    .map_err(|_| tr("Invalid maintenance minute", "维护时间的分钟格式不正确"))?;
                let time = jiff::civil::Time::new(hour, minute, 0, 0).map_err(|_| {
                    tr(
                        "Enter a time between 00:00 and 23:59",
                        "维护时间使用 00:00 至 23:59",
                    )
                })?;
                let now = jiff::Zoned::now();
                let mut date = now.date();
                for _ in 0..8 {
                    let at = date.to_datetime(time).to_zoned(now.time_zone().clone())?;
                    if at > now
                        && (self.calendar.weekdays.0.is_empty()
                            || self.calendar.weekdays.0.contains(&Day::from(at.weekday())))
                    {
                        return Ok(Some(now.duration_until(&at).unsigned_abs()));
                    }
                    date = date.tomorrow()?;
                }
                unreachable!("calendar schedule within a week")
            }
            Mode::Interval => {
                let interval = humantime::parse_duration(&self.interval).map_err(|error| {
                    message!(
                        "Invalid maintenance interval: {error}",
                        "维护间隔格式不正确：{error}"
                    )
                })?;
                if interval.is_zero() {
                    return Err(tr(
                        "Maintenance interval must be positive",
                        "维护间隔需要大于零",
                    )
                    .into());
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
    fn fields(&mut self, defaults: Self) -> form::Fields<'_> {
        let mode = self.mode;
        let mut fields = vec![
            form::field(
                "enabled",
                tr("Enabled", "启用"),
                &mut self.enabled,
                defaults.enabled,
            ),
            form::field(
                "mode",
                tr("Schedule type", "安排方式"),
                &mut self.mode,
                defaults.mode,
            ),
        ];
        match mode {
            Mode::Calendar => {
                fields.push(form::field(
                    "time",
                    tr("Time", "时间"),
                    &mut self.calendar.time,
                    defaults.calendar.time,
                ));
                fields.push(form::field(
                    "weekdays",
                    tr("Days", "星期"),
                    &mut self.calendar.weekdays,
                    defaults.calendar.weekdays,
                ));
            }
            Mode::Interval => fields.push(form::field(
                "interval",
                tr("Interval", "间隔"),
                &mut self.interval,
                defaults.interval,
            )),
        }
        fields
    }
}

impl Value for Weekdays {
    fn text(&self) -> String {
        if self.0.is_empty() {
            tr("Every day", "每天").to_owned()
        } else {
            self.0
                .iter()
                .map(Value::text)
                .collect::<Vec<_>>()
                .join(tr(", ", "、"))
        }
    }

    fn edit(&mut self, screen: &mut Screen, _: &Menu<'_>, _: usize) -> Result<bool> {
        let days = Day::choices();
        let mut selected = 0;
        let mut changed = false;
        loop {
            let mut items = vec![Item::new("daily", tr("Every day", "每天").stylized())];
            items[0].marker = self.0.is_empty().marker();
            for (key, label, day) in &days {
                let mut item = Item::new(*key, (*label).stylized());
                item.marker = self.0.contains(day).marker();
                items.push(item);
            }
            items.push(Item::new("back", tr("Back", "返回").stylized()));
            let menu = Menu {
                title: tr("Days", "星期"),
                heading: "",
                items: &items,
                help: tr(
                    "Arrow keys to select\nEnter to toggle\nEsc to go back",
                    "方向键 选择\n回车键 切换\nEsc 返回",
                ),
            };
            match screen.select(&menu, &mut selected, "")? {
                Action::Back => return Ok(changed),
                Action::Select if selected == items.len() - 1 => return Ok(changed),
                Action::Select => {
                    let mut next = self.clone();
                    if selected == 0 {
                        next.0.clear()
                    } else {
                        let day = days[selected - 1].2;
                        if next.0.contains(&day) {
                            next.0.retain(|value| *value != day);
                        } else {
                            next.0.push(day);
                            next.0.sort();
                        }
                        if next.0.len() == days.len() {
                            next.0.clear();
                        }
                    }
                    if *self != next {
                        *self = next;
                        changed = true;
                    }
                }
                _ => {}
            }
        }
    }
}

choices!(Mode {
    Calendar: "calendar" => ("Calendar", "日历安排"),
    Interval: "interval" => ("Fixed interval", "固定间隔"),
});

choices!(Day {
    Monday: "monday" => ("Monday", "周一"),
    Tuesday: "tuesday" => ("Tuesday", "周二"),
    Wednesday: "wednesday" => ("Wednesday", "周三"),
    Thursday: "thursday" => ("Thursday", "周四"),
    Friday: "friday" => ("Friday", "周五"),
    Saturday: "saturday" => ("Saturday", "周六"),
    Sunday: "sunday" => ("Sunday", "周日"),
});

pub fn update(store: &Store, progress: &Progress) -> Result<Option<crate::update::Installed>> {
    let config = store.load()?;
    let mut prepared = Resources::load(store)?;
    let update = component::update(store, &config, &mut prepared, progress)?;
    if prepared.geodata.is_some() {
        prepared.geodata = Some(Catalog::update(store, progress)?.release);
    }
    store.update(progress, |_, resources| {
        resources.components.extend(prepared.components);
        if let Some(release) = prepared.geodata {
            resources.geodata = Some(release);
        }
        Ok(())
    })?;
    update
        .map(|update| update.install(store, progress))
        .transpose()
}

pub fn rules(store: &Store, progress: &Progress) -> Result<()> {
    let catalog = Catalog::update(store, progress)?;
    store.update(progress, |_, resources| {
        resources.geodata = Some(catalog.release);
        Ok(())
    })
}

pub fn run(screen: &mut Screen, store: &Store) -> Result<Option<crate::update::Installed>> {
    let client = resource::client();
    let mut selected = 0;
    let mut notice = String::new();
    loop {
        let config = store.load()?;
        let resources = Resources::load(store)?;
        let mut running = Item::new("running", tr("Run service", "运行服务").stylized());
        running.marker = if config.running { "■" } else { "□" };
        let mut schedule = Item::new(
            "schedule",
            tr("Scheduled maintenance", "定时维护").stylized(),
        );
        schedule.value = if config.maintenance.enabled {
            tr("On", "开启")
        } else {
            tr("Off", "关闭")
        }
        .to_owned();
        let mut items = vec![
            running,
            Item::new("logs", tr("Logs", "运行日志").stylized()),
            Item::new(
                "rules",
                tr("Update routing data", "更新规则数据").stylized(),
            ),
            Item::new("update", tr("Update all", "更新全部").stylized()),
            schedule,
        ];
        items[2].gap = true;
        let versions = items.len();
        items.extend(Component::ALL.iter().map(|component| {
            let mut item = Item::new(component.key(), component.name().stylized());
            item.value = component
                .version(&resources)
                .unwrap_or(tr("Not installed", "未安装"))
                .to_owned();
            item
        }));
        items[versions].gap = true;
        items.push(Item::new("back", tr("Back", "返回").stylized()));
        let menu = Menu {
            title: tr("Maintenance", "维护"),
            heading: "",
            items: &items,
            help: tr(
                "Arrow keys to select\nEnter to confirm\nEsc to go back",
                "方向键 选择\n回车键 确定\nEsc 返回",
            ),
        };
        match screen.select(&menu, &mut selected, &notice)? {
            Action::Back => return Ok(None),
            Action::Select => {}
            _ => continue,
        }
        let result = if let Some(component) = Component::ALL
            .iter()
            .find(|component| component.key() == items[selected].key)
        {
            component::edit(screen, store, &client, *component)
        } else {
            match items[selected].key.as_str() {
                "running" => screen
                    .work(
                        if config.running {
                            tr("Stopping service", "停止服务")
                        } else {
                            tr("Starting service", "启动服务")
                        },
                        "",
                        |progress| {
                            store.update(progress, |config, _| {
                                config.running = !config.running;
                                Ok(())
                            })
                        },
                    )
                    .map(|()| None),
                "logs" => crate::service::logs(screen, store).map(|()| None),
                "rules" => screen
                    .work(
                        tr("Update routing data", "更新规则数据"),
                        "",
                        |progress| rules(store, progress),
                    )
                    .map(|()| None),
                "update" => screen.work(tr("Updating resources", "更新资源"), "", |progress| {
                    update(store, progress)
                }),
                "schedule" => form::page(
                    screen,
                    tr("Scheduled maintenance", "定时维护"),
                    &config.maintenance,
                    |settings: &Schedule, screen| {
                        screen.work(
                            tr("Updating maintenance schedule", "更新维护日程"),
                            "",
                            |progress| {
                                store.update(progress, |config, _| {
                                    config.maintenance = settings.clone();
                                    Ok(())
                                })
                            },
                        )
                    },
                )
                .map(|()| None),
                _ => return Ok(None),
            }
        };
        match result {
            Ok(Some(update)) => return Ok(Some(update)),
            Ok(None) => notice.clear(),
            Err(error) => notice = error.to_string(),
        }
    }
}
