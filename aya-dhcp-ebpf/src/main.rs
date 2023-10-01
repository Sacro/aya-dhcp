#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[xdp]
pub fn aya_dhcp(ctx: XdpContext) -> u32 {
    match try_aya_dhcp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

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

#[inline(always)]
fn is_broadcast_mac(mac: [u8; 6]) -> bool {
    true
    // mac == [u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX]
}

#[inline(always)]
fn is_dhcp_packet(source_port: u16, dest_port: u16) -> bool {
    (source_port == 68 && dest_port == 67) || (source_port == 67 && dest_port == 68)
}

fn try_aya_dhcp(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    if !is_broadcast_mac(unsafe { (*ethhdr).dst_addr }) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let _source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let _dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).source })
        }
        _ => return Err(()),
    };

    let dest_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be(unsafe { (*udphdr).dest })
        }
        _ => return Err(()),
    };

    if !is_dhcp_packet(source_port, dest_port) {
        return Ok(xdp_action::XDP_PASS);
    }

    info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
