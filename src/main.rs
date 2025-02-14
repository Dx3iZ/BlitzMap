use std::fs::File;
use std::io::{Write, Read};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task;
use tokio::time;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use colored::*;
use clap::{Parser};
use std::str::FromStr;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use chrono::{Local, Timelike, Datelike};
use locale_config::Locale;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP ünvanı və ya IP aralığı (məs: 192.168.1.1 və ya 192.168.1.1-100)
    #[arg(name = "target")]
    target: String,

    /// Port seçimləri:
    /// -p-: Bütün portları skan et (1-65535)
    /// -p <port>: Göstərilən portu skan et (məs: -p 80 və ya -p 80,443,8080)
    /// parametr daxil edilməzsə: İlk 1000 portu skan et
    #[arg(short = 'p', long, value_name = "PORT")]
    ports: Option<String>,

    /// Zaman aşımı müddəti (millisaniyə)
    #[arg(short = 't', long, default_value = "850")]
    timeout: u64,

    /// Rəngli çıxış
    #[arg(short = 'c', long)]
    colored: bool,

    /// Paralel skan sayı
    #[arg(short = 'j', long, default_value = "1000")]
    jobs: usize,

    /// Nəticələrin saxlanacağı fayl adı
    /// Göstərilməzsə 'blitzmap-[tarix].txt' olaraq saxlanılır
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<String>,

    /// Ətraflı çıxış rejimi
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
enum Protocol {
    TCP,
    UDP,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
        }
    }
}

#[derive(Debug, Clone)]
struct ServiceInfo {
    port: u16,
    protocol: Protocol,
    service_name: String,
    version: Option<String>,
    extra_info: Option<String>,
    service_type: Option<String>,
}

#[derive(Debug, Clone)]
struct PortRange {
    start: u16,
    end: u16,
    #[allow(dead_code)]
    category: String,
    description: String,
    ports: Vec<u16>,
}

struct ProtocolProbe {
    protocol: Protocol,
    data: Vec<u8>,
    service: &'static str,
    description: &'static str,
    default_port: u16,
}

fn get_protocol_probes() -> Vec<ProtocolProbe> {
    vec![
        // TCP Probes
        ProtocolProbe {
            protocol: Protocol::TCP,
            data: b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            service: "HTTP",
            description: "Web Server",
            default_port: 80,
        },
        ProtocolProbe {
            protocol: Protocol::TCP,
            data: b"HELP\r\n".to_vec(),
            service: "FTP",
            description: "File Transfer",
            default_port: 21,
        },
        ProtocolProbe {
            protocol: Protocol::TCP,
            data: b"EHLO test\r\n".to_vec(),
            service: "SMTP",
            description: "Mail Server",
            default_port: 25,
        },
        ProtocolProbe {
            protocol: Protocol::TCP,
            data: b"\x03\x00\x00\x13\x0E\xE0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00".to_vec(),
            service: "RDP",
            description: "Remote Desktop",
            default_port: 3389,
        },
        ProtocolProbe {
            protocol: Protocol::TCP,
            data: b"RFB 003.008\n".to_vec(),
            service: "VNC",
            description: "Remote Desktop",
            default_port: 5900,
        },
        // UDP Probes
        ProtocolProbe {
            protocol: Protocol::UDP,
            data: vec![0x00, 0x1e, 0x00, 0x06, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, 0x00, 0x10, 0x00, 0x03],
            service: "DNS",
            description: "Domain Name Server",
            default_port: 53,
        },
        ProtocolProbe {
            protocol: Protocol::UDP,
            data: vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02, 0x04, 0x71, 0xb4, 0xb5, 0x68, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00],
            service: "SNMP",
            description: "Network Management Protocol",
            default_port: 161,
        },
    ]
}

#[derive(Serialize, Deserialize)]
struct PortData {
    known_services: Vec<ServiceData>,
    popular_ports: Vec<u16>,
}

#[derive(Serialize, Deserialize)]
struct ServiceData {
    port: u16,
    name: String,
    description: String,
}

fn get_known_services() -> Vec<(u16, String, String)> {
    let port_data = load_port_data().unwrap_or_else(|e| {
        eprintln!("Error loading port data: {}", e);
        std::process::exit(1);
    });

    port_data.known_services
        .into_iter()
        .map(|s| (s.port, s.name, s.description))
        .collect()
}

fn get_popular_ports() -> Vec<u16> {
    load_port_data()
        .map(|data| data.popular_ports)
        .unwrap_or_else(|_| vec![80, 443, 8080]) // Fallback to basic ports if file can't be loaded
}

fn load_port_data() -> Result<PortData, Box<dyn std::error::Error>> {
    let mut file = File::open("src/port_data.json")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(serde_json::from_str(&contents)?)
}

fn get_localized_time() -> String {
    let locale = Locale::current();
    let lang = locale.tags()
        .next()
        .map(|(lang, _)| lang)
        .unwrap_or(Some("en"))
        .unwrap_or("en");
    
    let now = Local::now();
    
    match lang {
        "tr" => {
            let time_str = if now.minute() == 0 {
                format!("{}:00", now.hour())
            } else {
                format!("{}:{:02}", now.hour(), now.minute())
            };
            
            format!("{} {} {} - {}", 
                now.day(), 
                match now.month() {
                    1 => "Ocak", 2 => "Şubat", 3 => "Mart", 4 => "Nisan",
                    5 => "Mayıs", 6 => "Haziran", 7 => "Temmuz", 8 => "Ağustos",
                    9 => "Eylül", 10 => "Ekim", 11 => "Kasım", 12 => "Aralık",
                    _ => "",
                },
                now.year(),
                time_str
            )
        },
        _ => {
            let time_str = if now.minute() == 0 {
                format!("{}:00", now.hour())
            } else {
                format!("{}:{:02}", now.hour(), now.minute())
            };
            
            format!("{} {}, {} - {}", 
                match now.month() {
                    1 => "January", 2 => "February", 3 => "March", 4 => "April",
                    5 => "May", 6 => "June", 7 => "July", 8 => "August",
                    9 => "September", 10 => "October", 11 => "November", 12 => "December",
                    _ => "",
                },
                now.day(),
                now.year(),
                time_str
            )
        },
    }
}

async fn get_service_info(stream: &mut TcpStream, port: u16) -> ServiceInfo {
    let mut buffer = [0; 4096];
    let mut service_info = ServiceInfo {
        port,
        protocol: Protocol::TCP,
        service_name: String::from("unknown"),
        version: None,
        extra_info: None,
        service_type: None,
    };

    // Bilinen servisleri kontrol et
    if let Some((_, service_name, service_type)) = get_known_services()
        .iter()
        .find(|(p, _, _)| *p == port) {
        service_info.service_name = service_name.clone();
        service_info.service_type = Some(service_type.clone());
    }

    for probe in get_protocol_probes().iter().filter(|p| matches!(p.protocol, Protocol::TCP)) {
        if let Ok(_) = stream.write_all(&probe.data).await {
            if let Ok(n) = stream.read(&mut buffer).await {
                if n > 0 {
                    let response = String::from_utf8_lossy(&buffer[..n]);
                    if response.contains(probe.service) {
                        service_info.version = Some(response.trim().to_string());
                        
                        // Özel protokol işlemleri
                        match probe.service {
                            "RDP" => {
                                if response.contains("NTLM") {
                                    service_info.extra_info = Some("Windows Authentication".to_string());
                                }
                            },
                            "VNC" => {
                                if let Some(version) = response.lines().next() {
                                    service_info.version = Some(version.to_string());
                                }
                            },
                            _ => {}
                        }
                        break;
                    }
                }
            }
        }
        time::sleep(Duration::from_millis(10)).await;
    }

    service_info
}

async fn scan_tcp_port(
    tx: mpsc::Sender<ServiceInfo>, 
    ip: IpAddr, 
    port: u16, 
    timeout: Duration,
) {
    let address = (ip, port);
    let connect_future = TcpStream::connect(&address);

    match time::timeout(timeout, connect_future).await {
        Ok(Ok(mut stream)) => {
            let service_info = get_service_info(&mut stream, port).await;
            let _ = tx.send(service_info).await;
        }
        _ => {}
    }
}

async fn scan_udp_port(
    tx: mpsc::Sender<ServiceInfo>, 
    ip: IpAddr, 
    port: u16, 
    timeout: Duration,
) {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return,
    };

    let address = format!("{}:{}", ip, port);
    if socket.connect(&address).await.is_err() {
        return;
    }

    for probe in get_protocol_probes().iter().filter(|p| matches!(p.protocol, Protocol::UDP)) {
        if probe.default_port == port {
            if socket.send(&probe.data).await.is_ok() {
                let mut buf = [0; 4096];
                match time::timeout(timeout, socket.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        let response = String::from_utf8_lossy(&buf[..n]);
                        let _ = tx.send(ServiceInfo {
                            port,
                            protocol: Protocol::UDP,
                            service_name: format!("{} ({})", probe.service, probe.description),
                            version: Some(response.trim().to_string()),
                            extra_info: None,
                            service_type: None,
                        }).await;
                        return;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn format_colored_text(text: &str, colored: bool, color_fn: fn(&str) -> ColoredString) -> String {
    if colored {
        color_fn(text).to_string()
    } else {
        text.to_string()
    }
}

async fn scan_port_range(
    ip: IpAddr, 
    range: PortRange,
    timeout: Duration,
    colored: bool,
    jobs: usize,
) -> Vec<ServiceInfo> {
    let (tx, mut rx) = mpsc::channel(jobs);
    let mut tasks = FuturesUnordered::new();
    
    let ports_to_scan: Vec<u16> = if !range.ports.is_empty() {
        range.ports
    } else {
        (range.start..=range.end).collect()
    };
    
    let total_ports = ports_to_scan.len();
    let pb = ProgressBar::new(total_ports as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    let scanning_text = format_colored_text("Scanning:", colored, |s| s.bright_blue());
    let msg = format!("\n{} {} ({} ports)", 
        scanning_text,
        range.description,
        total_ports
    );
    println!("{}", msg);

    for port in ports_to_scan {
        let tx_tcp = tx.clone();
        let tx_udp = tx.clone();
        
        tasks.push(task::spawn(scan_tcp_port(
            tx_tcp, 
            ip, 
            port, 
            timeout,
        )));
        
        if port <= 1024 || get_protocol_probes().iter().any(|p| p.default_port == port) {
            tasks.push(task::spawn(scan_udp_port(
                tx_udp, 
                ip, 
                port, 
                timeout,
            )));
        }

        if tasks.len() >= jobs {
            while let Some(_) = tasks.next().await {
                pb.inc(1);
                if tasks.len() < jobs / 2 {
                    break;
                }
            }
        }
    }

    drop(tx);

    // Kalan tüm task'ları tamamla
    while let Some(_) = tasks.next().await {
        pb.inc(1);
    }

    let mut results = Vec::new();
    while let Ok(info) = rx.try_recv() {
        results.push(info);
    }

    pb.finish_with_message("Scan completed");
    
    results.sort_by(|a, b| a.port.cmp(&b.port));
    results
}

#[derive(Debug, Clone)]
struct IpRange {
    start: Ipv4Addr,
    end: Ipv4Addr,
}

impl FromStr for IpRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('-') {
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() != 2 {
                return Err("Invalid IP range format".to_string());
            }

            let start_ip = parts[0].parse::<Ipv4Addr>()
                .map_err(|_| "Invalid start IP address")?;
            
            let end_octet = parts[1].parse::<u8>()
                .map_err(|_| "Invalid end octet")?;
            
            let mut end_ip_octets = start_ip.octets();
            end_ip_octets[3] = end_octet;
            
            Ok(IpRange {
                start: start_ip,
                end: Ipv4Addr::from(end_ip_octets),
            })
        } else {
            let ip = s.parse::<Ipv4Addr>()
                .map_err(|_| "Invalid IP address")?;
            Ok(IpRange {
                start: ip,
                end: ip,
            })
        }
    }
}

fn format_port_info(info: &ServiceInfo, colored: bool, verbose: bool) -> (String, String) {
    let port_str = format!("{}/{}", info.port, info.protocol.to_string().to_lowercase());
    let state_str = "open";
    let service_str = &info.service_name;
    
    let version_str = if verbose {
        if let Some(version) = &info.version {
            format!("\n{}", version.trim())
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let service_info = if verbose {
        if let Some(service_type) = &info.service_type {
            format!("\n         ╰─> {}", service_type)
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let extra_info = if verbose {
        if let Some(extra) = &info.extra_info {
            format!("\n             ├─> {}", extra)
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let colored_output = if colored {
        if verbose {
            format!("{:<9} {:<6} {}{}{}{}", 
                port_str.bright_green(),
                state_str.bright_blue(),
                service_str.bright_yellow(),
                version_str.bright_cyan(),
                service_info.bright_white(),
                extra_info.bright_magenta()
            )
        } else {
            format!("{:<9} {:<6} {:<20}", 
                port_str.bright_green(),
                state_str.bright_blue(),
                service_str.bright_yellow()
            )
        }
    } else {
        if verbose {
            format!("{:<9} {:<6} {}{}{}{}", 
                port_str, state_str, 
                service_str,
                version_str,
                service_info,
                extra_info
            )
        } else {
            format!("{:<9} {:<6} {:<20}", 
                port_str, state_str, service_str
            )
        }
    };

    let plain_output = format!("{:<9} {:<6} {}{}{}{}", 
        port_str, state_str, service_str, version_str, service_info, extra_info
    );

    (colored_output, plain_output)
}

fn parse_port_argument(port_arg: Option<String>) -> Vec<PortRange> {
    match port_arg {
        None => {
            // Heç bir parametr daxil edilmədikdə, ən populyar portlar
            let popular_ports = get_popular_ports();
            vec![PortRange {
                start: 0,
                end: 0,
                category: String::from("Popular Ports"),
                description: String::from("Most Common Ports (BlitzMap Default)"),
                ports: popular_ports,
            }]
        },
        Some(arg) => {
            if arg == "-" {
                // -p- status: Bütün portlar
                vec![PortRange {
                    start: 1,
                    end: 65535,
                    category: String::from("All Ports"),
                    description: String::from("Full Port Scan"),
                    ports: vec![],
                }]
            } else {
                // -p <port> statusu: vergüllə ayrılmış portlar
                let ports: Vec<u16> = arg.split(',')
                    .filter_map(|p| p.trim().parse::<u16>().ok())
                    .collect();

                if ports.is_empty() {
                    eprintln!("Error: Invalid port number: {}", arg);
                    std::process::exit(1);
                }

                vec![PortRange {
                    start: 0,
                    end: 0,
                    category: String::from("Specified Ports"),
                    description: format!("Specified Ports ({})", arg),
                    ports,
                }]
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    
    let ip_range = IpRange::from_str(&args.target).unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    });

    let timeout = Duration::from_millis(args.timeout);
    let categories = parse_port_argument(args.ports);

    let start_time = Instant::now();

    let app_header = format!("\n{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let time_info = get_localized_time();
    let locale = Locale::current();
    let country = locale.tags()
        .next()
        .map(|(_, range)| range.to_string().split("-").last().unwrap_or("Unknown").to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    
    println!("{}", "═".repeat(80));
    println!("{}", format!("{} - {}", app_header.bright_cyan(), time_info.bright_yellow()));
    println!("Location: {}", country.bright_green());
    println!("{}", "═".repeat(80));

    let mut output_file = args.output.map(|filename| {
        File::create(&filename).unwrap_or_else(|e| {
            eprintln!("Error: Could not create file '{}': {}", filename, e);
            std::process::exit(1);
        })
    });

    if let Some(file) = &mut output_file {
        writeln!(file, "{}", app_header).expect("Failed to write to file");
        writeln!(file, "{}", time_info).expect("Failed to write to file");
        writeln!(file, "{}", "═".repeat(80)).expect("Failed to write to file");
    }

    let mut total_results = Vec::new();
    
    let start_ip = u32::from(ip_range.start);
    let end_ip = u32::from(ip_range.end);
    
    for ip_int in start_ip..=end_ip {
        let current_ip = Ipv4Addr::from(ip_int);
        let ip_header = format!("\nScanning IP: {}", current_ip);
        let colored_ip_header = format_colored_text(&ip_header, args.colored, |s| s.bright_blue());
        println!("{}", colored_ip_header);
        
        if let Some(file) = &mut output_file {
            writeln!(file, "{}", ip_header).expect("Failed to write to file");
        }

        for range in &categories {
            let mut results = scan_port_range(
                IpAddr::V4(current_ip),
                range.clone(),
                timeout,
                args.colored,
                args.jobs
            ).await;
            
            if !results.is_empty() {
                let header = format!("\n{:<9} {:<6} {}", "PORT", "STATE", "SERVICE");
                let colored_header = format_colored_text(&header, args.colored, |s| s.bright_yellow());
                println!("{}", colored_header);
                println!("{}", "─".repeat(50));
                
                if let Some(file) = &mut output_file {
                    writeln!(file, "{}", header).expect("Failed to write to file");
                }
                
                let (tcp_results, udp_results): (Vec<_>, Vec<_>) = results.clone().into_iter()
                    .partition(|info| matches!(info.protocol, Protocol::TCP));

                if !tcp_results.is_empty() {
                    for info in tcp_results {
                        let (colored_output, plain_output) = format_port_info(&info, args.colored, args.verbose);
                        println!("{}", colored_output);
                        
                        if let Some(file) = &mut output_file {
                            writeln!(file, "{}", plain_output).expect("Failed to write to file");
                        }
                    }
                }

                if !udp_results.is_empty() {
                    for info in udp_results {
                        let (colored_output, plain_output) = format_port_info(&info, args.colored, args.verbose);
                        println!("{}", colored_output);
                        
                        if let Some(file) = &mut output_file {
                            writeln!(file, "{}", plain_output).expect("Failed to write to file");
                        }
                    }
                }
            }
            total_results.append(&mut results);
        }
    }

    let duration = start_time.elapsed().as_secs_f64();
    let minutes = (duration / 60.0).floor();
    let seconds = duration % 60.0;
    
    let open_ports = total_results.len();
    let total_ports = categories.iter()
        .map(|range| if range.ports.is_empty() {
            range.end - range.start + 1
        } else {
            range.ports.len() as u16
        })
        .sum::<u16>();
    
    let time_str = if minutes > 0.0 {
        format!("{:.0} minutes {:.0} seconds", minutes, seconds)
    } else {
        format!("{:.1} seconds", seconds)
    };
    
    let summary = format!(
        "\nScan completed!\nTotal ports scanned: {}\nOpen ports found: {}\nTime elapsed: {}", 
        total_ports, open_ports, time_str
    );
    
    let colored_summary = format_colored_text(&summary, args.colored, |s| s.bright_green());
    println!("{}", colored_summary);
    
    if let Some(file) = &mut output_file {
        writeln!(file, "{}", summary).expect("Failed to write to file");
    }
}