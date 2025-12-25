#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{debug, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[inline(always)] // (1)
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn sanitize_dns(ctx: XdpContext) -> u32 {
    match try_sanitize_dns(&ctx) {
        Ok(ret) => ret,
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_sanitize_dns(ctx: &XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;
    if unsafe { (*ethhdr).ether_type } != u16::from(EtherType::Ipv4) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    let protocol = unsafe { (*ipv4hdr).proto };
    let proto_str = protocol_to_str(protocol);

    let source_port = match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be_bytes(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe { (*udphdr).src_port() }
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    if source_port != 53 {
        return Ok(xdp_action::XDP_PASS);
    };

    // drop if ID is 0
    if unsafe { (*ipv4hdr).id() } == 0 {
        info!(
            ctx,
            "Dropping packet from {:i} port {} proto {} with ID 0",
            source_addr,
            source_port,
            proto_str
        );
        return Ok(xdp_action::XDP_DROP);
    }

    // FIXME: This can cause legitimate packets to be dropped
    // drop if DF flag is set (may be a DNS response with no answers)

    // if unsafe { (*ipv4hdr).frag_flags() } & 0x2 != 0 {
    //     info!(
    //         ctx,
    //         "Dropping packet from {:i} port {} with DF flag set",
    //         source_addr,
    //         source_port,
    //         proto_str
    //     );
    //     return Ok(xdp_action::XDP_DROP);
    // }

    if protocol == IpProto::Udp {
        // DNS header starts after UDP header (8 bytes)
        let dns_offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN;
        return check_dns_header(ctx, dns_offset, source_addr);
    }

    // Handle DNS over TCP
    if protocol == IpProto::Tcp {
        let tcphdr: *const TcpHdr = ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
        // TCP data offset is in top 4 bits, in 32-bit words
        let tcp_header_len = ((unsafe { (*tcphdr).doff() }) as usize) * 4;

        // DNS over TCP has 2-byte length prefix before DNS message
        let dns_offset = EthHdr::LEN + Ipv4Hdr::LEN + tcp_header_len + 2;
        return check_dns_header(ctx, dns_offset, source_addr);
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn protocol_to_str(proto: IpProto) -> &'static str {
    match proto {
        IpProto::Tcp => "TCP",
        IpProto::Udp => "UDP",
        _ => "OTHER",
    }
}

#[inline(always)]
fn check_dns_header(ctx: &XdpContext, dns_offset: usize, source_addr: u32) -> Result<u32, ()> {
    // Read DNS flags (bytes 2-3)
    let dns_flags_ptr: *const [u8; 2] = ptr_at(ctx, dns_offset + 2)?;
    let dns_flags = u16::from_be_bytes(unsafe { *dns_flags_ptr });

    // Drop if AA (Authoritative Answer) flag is set (bit 10, mask 0x0400)
    if dns_flags & 0x0400 != 0 {
        debug!(
            ctx,
            "Dropping DNS packet from {:i} with AA flag set", source_addr
        );
        return Ok(xdp_action::XDP_DROP);
    }

    // Read Answer RRs (bytes 6-7)
    let answer_rrs_ptr: *const [u8; 2] = ptr_at(ctx, dns_offset + 6)?;
    let answer_rrs = u16::from_be_bytes(unsafe { *answer_rrs_ptr });

    // Read Authority RRs (bytes 8-9)
    let authority_rrs_ptr: *const [u8; 2] = ptr_at(ctx, dns_offset + 8)?;
    let authority_rrs = u16::from_be_bytes(unsafe { *authority_rrs_ptr });

    // Pass if multiple answers or has authority answers
    if answer_rrs > 1 || authority_rrs > 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
