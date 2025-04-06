#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

/// Безопасное получение указателя с проверкой границ: offset + размер T должен быть внутри пакета.
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // Парсим заголовок Ethernet.
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    info!(&ctx, "Ethernet header parsed");

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Парсим IPv4-заголовок.
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, ETH_HDR_LEN)?;
    let src_ip = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    info!(
        &ctx,
        "IPv4 header parsed: SRC IP: {:i}, DST IP: {:i}",
        src_ip,
        dst_ip
    );

    // Определяем страну по упрощённой логике (на основе первого октета)
    let country = lookup_country(src_ip);
    info!(&ctx, "Traffic originates from country: {}", country);

    // Извлекаем только исходный порт, используя фиксированное смещение.
    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN)?;
            u16::from_be(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, ETH_HDR_LEN + IPV4_HDR_LEN)?;
            u16::from_be(unsafe { (*udphdr).source })
        }
        _ => {
            info!(&ctx, "Unsupported protocol, dropping");
            return Ok(xdp_action::XDP_DROP);
        }
    };

    info!(&ctx, "Parsed source port: {}", source_port);

    // Разрешённые входящие порты HTTP/HTTPS.
    const ALLOWED_HTTP: u16 = 80;
    const ALLOWED_HTTPS: u16 = 443;

    if source_port == ALLOWED_HTTP || source_port == ALLOWED_HTTPS || source_port == 53 {
        info!(
            &ctx,
            "Allowed traffic: packet from {:i}:{}",
            src_ip,
            source_port
        );
        Ok(xdp_action::XDP_PASS)
    } else {
        info!(
            &ctx,
            "Blocked traffic: packet from {:i}:{}",
            src_ip,
            source_port
        );
        Ok(xdp_action::XDP_DROP)
    }
}

/// Функция определения "страны" по первому октету IP-адреса.
///
/// Это упрощённая демонстрационная логика, где для разных значений
/// первого октета возвращаются различные коды стран. В реальном приложении
/// необходимо использовать корректную базу данных IP-диапазонов.
fn lookup_country(src_ip: u32) -> &'static str {
    let first_octet = (src_ip >> 24) as u8;
    match first_octet {
        1  => "US", // Соединённые Штаты
        2  => "CA", // Канада
        3  => "MX", // Мексика
        4  => "BR", // Бразилия
        5  => "RU", // Россия
        6  => "CN", // Китай
        7  => "IN", // Индия
        8  => "GB", // Великобритания
        9  => "DE", // Германия
        10 => "FR", // Франция
        11 => "ES", // Испания
        12 => "IT", // Италия
        13 => "AU", // Австралия
        14 => "JP", // Япония
        15 => "KR", // Южная Корея
        16 => "SE", // Швеция
        17 => "NO", // Норвегия
        18 => "FI", // Финляндия
        19 => "DK", // Дания
        20 => "NL", // Нидерланды
        21 => "BE", // Бельгия
        22 => "CH", // Швейцария
        23 => "AT", // Австрия
        24 => "PL", // Польша
        25 => "CZ", // Чехия
        26 => "SK", // Словакия
        27 => "HU", // Венгрия
        28 => "RO", // Румыния
        29 => "BG", // Болгария
        30 => "TR", // Турция
        // Можно добавить остальные необходимые страны.
        _  => "OTHER",
    }
}
