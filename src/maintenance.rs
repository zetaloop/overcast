use termina::style::StyleExt;

use crate::{
    Result,
    component::{self, Component},
    config::Store,
    geodata::Catalog,
    progress::Progress,
    resource::{self, Resources},
    tui::{Action, Item, Menu, Screen},
};

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
        items.extend([
            running,
            Item::new("rules", "更新规则数据".stylized()),
            Item::new("update", "更新全部".stylized()),
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
                _ => return Ok(()),
            }
        };
        notice = result
            .err()
            .map_or_else(String::new, |error| error.to_string());
    }
}
