use std::sync::mpsc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrayAction {
    Show,
    Hide,
    Quit,
}

pub struct Tray {
    #[cfg(target_os = "linux")]
    _handle: ksni::blocking::Handle<LinuxTray>,
    #[cfg(target_os = "linux")]
    rx: mpsc::Receiver<TrayAction>,

    #[cfg(not(target_os = "linux"))]
    tray_icon: tray_icon::TrayIcon,
    #[cfg(not(target_os = "linux"))]
    menu_ids: MenuIds,
}

impl Tray {
    pub fn init(app_name: &str) -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let (tx, rx) = mpsc::channel();
            let tray = LinuxTray::new(app_name.to_string(), tx);
            let handle = ksni::blocking::TrayMethods::spawn(tray)?;
            Ok(Self {
                _handle: handle,
                rx,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            use tray_icon::menu::{Menu, MenuItem, Submenu};

            let icon = tray_icon::Icon::from_rgba(vec![0, 0, 0, 0], 1, 1)?;
            let menu = Menu::new();
            let root = Submenu::new(app_name, true);

            let show = MenuItem::new("Show", true, None);
            let hide = MenuItem::new("Hide", true, None);
            let quit = MenuItem::new("Quit", true, None);

            root.append(&show)?;
            root.append(&hide)?;
            root.append(&quit)?;
            menu.append(&root)?;

            let tray_icon = tray_icon::TrayIconBuilder::new()
                .with_tooltip(app_name)
                .with_menu(Box::new(menu))
                .with_icon(icon)
                .build()?;

            let menu_ids = MenuIds {
                show: show.id().clone(),
                hide: hide.id().clone(),
                quit: quit.id().clone(),
            };

            return Ok(Self {
                tray_icon,
                menu_ids,
            });
        }
    }

    pub fn try_recv(&self) -> Option<TrayAction> {
        #[cfg(target_os = "linux")]
        {
            self.rx.try_recv().ok()
        }

        #[cfg(not(target_os = "linux"))]
        {
            if let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
                if event.id == self.menu_ids.show {
                    return Some(TrayAction::Show);
                }
                if event.id == self.menu_ids.hide {
                    return Some(TrayAction::Hide);
                }
                if event.id == self.menu_ids.quit {
                    return Some(TrayAction::Quit);
                }
            }

            if let Ok(event) = tray_icon::TrayIconEvent::receiver().try_recv() {
                use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};

                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    return Some(TrayAction::Show);
                }
            }

            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug)]
struct MenuIds {
    show: tray_icon::menu::MenuId,
    hide: tray_icon::menu::MenuId,
    quit: tray_icon::menu::MenuId,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxTray {
    app_name: String,
    tx: mpsc::Sender<TrayAction>,
}

#[cfg(target_os = "linux")]
impl LinuxTray {
    fn new(app_name: String, tx: mpsc::Sender<TrayAction>) -> Self {
        Self { app_name, tx }
    }
}

#[cfg(target_os = "linux")]
impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        self.app_name.clone()
    }

    fn title(&self) -> String {
        self.app_name.clone()
    }

    fn icon_name(&self) -> String {
        "application-x-executable".to_string()
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;

        let tx_show = self.tx.clone();
        let tx_hide = self.tx.clone();
        let tx_quit = self.tx.clone();

        vec![
            StandardItem {
                label: "Show".into(),
                activate: Box::new(move |_| {
                    let _ = tx_show.send(TrayAction::Show);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Hide".into(),
                activate: Box::new(move |_| {
                    let _ = tx_hide.send(TrayAction::Hide);
                }),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(move |_| {
                    let _ = tx_quit.send(TrayAction::Quit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}
