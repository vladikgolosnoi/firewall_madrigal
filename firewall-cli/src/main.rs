use dialoguer::{Input, Select};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use pnet::datalink;

fn main() {
    ensure_config_exists();

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = Arc::clone(&running);
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Ошибка установки обработчика Ctrl+C");
    }

    loop {
        // Сброс флага перед каждым запуском
        running.store(true, Ordering::SeqCst);

        if !show_main_menu(&running) {
            break;
        }
    }

    println!("Программа завершена.");
}

fn show_main_menu(running: &Arc<AtomicBool>) -> bool {
    clear_screen();
    println!("Выберите действие:");
    let items = vec![
        "1. Запустить файрволл",
        "2. Настроить конфигурацию",
        "3. Выбрать интерфейс",
        "4. Выход",
    ];

    let selection = Select::new().items(&items).default(0).interact();

    match selection {
        Ok(choice) => match choice {
            0 => run_firewall(running),
            1 => configure_file(),
            2 => choose_interface(),
            3 => return false, // выход
            _ => {}
        },
        Err(e) => {
            if e.to_string().contains("interrupted") {
                println!("\nВвод прерван пользователем (Ctrl+C). Возврат в меню...");
            } else {
                println!("\nОшибка ввода: {e}");
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    true
}

fn clear_screen() {
    print!("{esc}c", esc = 27 as char);
    let _ = std::io::stdout().flush();
}

fn ensure_config_exists() {
    let path = "config.cfg";
    if !Path::new(path).exists() {
        let default = "\"iface\"\neth0\n\"allowed-ports\"\n80, 443\n\"blocked-ips\"\n\n\"blocked-countries\"\n";
        fs::write(path, default).expect("Не удалось создать config.cfg");
    }
}

fn run_firewall(running: &Arc<AtomicBool>) {
    println!("Запуск файрволла (нажмите Ctrl+C для возврата в меню)");

    let config = parse_config("config.cfg");
    let iface = config.get("iface").cloned().unwrap_or_else(|| "eth0".to_string());

    let ports = config
        .get("allowed-ports")
        .unwrap_or(&String::new())
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    let blocked_ips = config
        .get("blocked-ips")
        .unwrap_or(&String::new())
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    let blocked_countries = config
        .get("blocked-countries")
        .unwrap_or(&String::new())
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    let mut parts = vec![format!("--iface {}", iface.trim())];

    if !ports.is_empty() {
        parts.push(format!("--ports {}", ports));
    }

    if !blocked_ips.is_empty() {
        parts.push(format!("--blocked-ips {}", blocked_ips));
    }

    if !blocked_countries.is_empty() {
        parts.push(format!("--blocked-countries {}", blocked_countries));
    }

    let final_command = format!("firewall");

    println!("Выполняется команда:\n");
    println!("sudo {}\n", final_command);
    println!("Сервис запущен :)");

    let _ = Command::new("sudo").
    arg(&final_command).
    status();


    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    println!("\nФайрволл остановлен. Возврат в главное меню...");
}

fn configure_file() {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "nano".to_string());

    match Command::new(editor).arg("config.cfg").status() {
        Ok(status) if status.success() => {}
        Ok(_) => println!("Редактор завершился с ошибкой."),
        Err(e) => println!("Ошибка запуска редактора: {e}"),
    }
}

fn choose_interface() {
    println!("Выберите интерфейс:");

    let interfaces: Vec<_> = datalink::interfaces()
        .into_iter()
        .filter(|iface| iface.name != "lo")
        .collect();

    for (i, iface) in interfaces.iter().enumerate() {
        println!("{}. {}", i + 1, iface.name);
    }

    let iface_input: Result<String, _> = Input::new()
        .with_prompt("Введите номер или имя интерфейса")
        .interact_text();

    match iface_input {
        Ok(input) => {
            let selected_iface = if let Ok(index) = input.parse::<usize>() {
                interfaces.get(index - 1).map(|iface| iface.name.clone())
            } else {
                Some(input.clone())
            };

            match selected_iface {
                Some(name) => {
                    update_config_iface(&name);
                    println!("Интерфейс '{}' сохранён в config.cfg", name);
                }
                None => println!("Некорректный выбор интерфейса."),
            }
        }
        Err(e) => {
            if e.to_string().contains("interrupted") {
                println!("Ввод прерван пользователем (Ctrl+C). Возврат в меню...");
            } else {
                println!("Ошибка ввода: {e}. Возврат в меню...");
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
}

fn update_config_iface(new_iface: &str) {
    let path = "config.cfg";

    let content = fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

    let mut found_iface = false;

    for i in 0..lines.len() {
        if lines[i].trim() == "\"iface\"" {
            if i + 1 < lines.len() {
                lines[i + 1] = new_iface.to_string();
                found_iface = true;
                break;
            }
        }
    }

    if !found_iface {
        lines.push("\"iface\"".to_string());
        lines.push(new_iface.to_string());
    }

    if !lines.iter().any(|l| l.trim() == "\"allowed-ports\"") {
        lines.push("\"allowed-ports\"".to_string());
        lines.push("80, 443".to_string());
    }

    if !lines.iter().any(|l| l.trim() == "\"blocked-ips\"") {
        lines.push("\"blocked-ips\"".to_string());
        lines.push("".to_string());
    }

    if !lines.iter().any(|l| l.trim() == "\"blocked-countries\"") {
        lines.push("\"blocked-countries\"".to_string());
        lines.push("".to_string());
    }

    let updated = lines.join("\n");
    fs::write(path, updated).expect("Не удалось записать конфигурацию");
}

fn parse_config(path: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let content = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();

    let mut i = 0;
    while i < lines.len() {
        let key = lines[i].trim().trim_matches('"');
        if i + 1 < lines.len() {
            let value = lines[i + 1].trim();
            map.insert(key.to_string(), value.to_string());
            i += 2;
        } else {
            i += 1;
        }
    }

    map
}
