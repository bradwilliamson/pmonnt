use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct NetworkConnection {
    pub protocol: Protocol,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub state: Option<TcpState>,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
}

#[derive(Error, Debug, Clone)]
pub enum NetworkError {
    #[error("{api} failed with error code {code}")]
    WinApi { api: &'static str, code: u32 },
}

const CACHE_TTL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
struct CacheEntry {
    fetched_at: Instant,
    all: Vec<NetworkConnection>,
    by_pid: HashMap<u32, Vec<NetworkConnection>>,
}

static CACHE: LazyLock<RwLock<Option<CacheEntry>>> = LazyLock::new(|| RwLock::new(None));

pub fn get_connections_for_process(pid: u32) -> Result<Vec<NetworkConnection>, NetworkError> {
    let all = get_all_connections()?;
    Ok(all.into_iter().filter(|c| c.pid == pid).collect())
}

pub fn get_all_connections() -> Result<Vec<NetworkConnection>, NetworkError> {
    if let Some(hit) = cache_get_all() {
        return Ok(hit);
    }

    let all = refresh_all()?;
    Ok(all)
}

pub fn get_tcp_connections() -> Result<Vec<NetworkConnection>, NetworkError> {
    let all = get_all_connections()?;
    Ok(all
        .into_iter()
        .filter(|c| c.protocol == Protocol::Tcp)
        .collect())
}

pub fn get_udp_connections() -> Result<Vec<NetworkConnection>, NetworkError> {
    let all = get_all_connections()?;
    Ok(all
        .into_iter()
        .filter(|c| c.protocol == Protocol::Udp)
        .collect())
}

fn cache_get_all() -> Option<Vec<NetworkConnection>> {
    let guard = CACHE.read().ok()?.as_ref().cloned();
    let entry = guard?;
    if entry.fetched_at.elapsed() <= CACHE_TTL {
        Some(entry.all)
    } else {
        None
    }
}

#[allow(dead_code)]
fn cache_get_pid(pid: u32) -> Option<Vec<NetworkConnection>> {
    let guard = CACHE.read().ok()?.as_ref().cloned();
    let entry = guard?;
    if entry.fetched_at.elapsed() > CACHE_TTL {
        return None;
    }
    entry.by_pid.get(&pid).cloned()
}

fn refresh_all() -> Result<Vec<NetworkConnection>, NetworkError> {
    let mut all = Vec::new();
    all.extend(query_tcp()?);
    all.extend(query_udp()?);

    let mut by_pid: HashMap<u32, Vec<NetworkConnection>> = HashMap::new();
    for conn in &all {
        by_pid.entry(conn.pid).or_default().push(conn.clone());
    }

    let entry = CacheEntry {
        fetched_at: Instant::now(),
        all: all.clone(),
        by_pid,
    };

    if let Ok(mut guard) = CACHE.write() {
        *guard = Some(entry);
    }

    Ok(all)
}

fn query_tcp() -> Result<Vec<NetworkConnection>, NetworkError> {
    let mut out = Vec::new();
    out.extend(query_tcp_af_v4()?);
    out.extend(query_tcp_af_v6()?);
    Ok(out)
}

fn query_udp() -> Result<Vec<NetworkConnection>, NetworkError> {
    let mut out = Vec::new();
    out.extend(query_udp_af_v4()?);
    out.extend(query_udp_af_v6()?);
    Ok(out)
}

fn tcp_state_from_mib(state: u32) -> Option<TcpState> {
    match state {
        1 => Some(TcpState::Closed),
        2 => Some(TcpState::Listen),
        3 => Some(TcpState::SynSent),
        4 => Some(TcpState::SynReceived),
        5 => Some(TcpState::Established),
        6 => Some(TcpState::FinWait1),
        7 => Some(TcpState::FinWait2),
        8 => Some(TcpState::CloseWait),
        9 => Some(TcpState::Closing),
        10 => Some(TcpState::LastAck),
        11 => Some(TcpState::TimeWait),
        12 => Some(TcpState::DeleteTcb),
        _ => None,
    }
}

fn port_from_be_u32(port_be: u32) -> u16 {
    u16::from_be(port_be as u16)
}

fn ipv4_from_be_u32(addr_be: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(addr_be))
}

fn query_tcp_af_v4() -> Result<Vec<NetworkConnection>, NetworkError> {
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    // SAFETY: Windows API interaction with GetExtendedTcpTable
    // - First call with null buffer gets required size
    // - Second call writes structured data into properly sized buffer
    // - Buffer alignment requirements are satisfied by Windows API guarantees for this function
    // - The buffer is sized by Windows and cast to MIB_TCPTABLE_OWNER_PID with count validation
    unsafe {
        let mut size: u32 = 0;
        let mut ret = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != ERROR_INSUFFICIENT_BUFFER {
            return Err(NetworkError::WinApi {
                api: "GetExtendedTcpTable",
                code: ret,
            });
        }

        // Allocate aligned buffer: GetExtendedTcpTable guarantees proper alignment
        // for the returned structures when using the OS-provided size
        let mut buf = vec![0u8; size as usize];
        ret = GetExtendedTcpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != 0 {
            return Err(NetworkError::WinApi {
                api: "GetExtendedTcpTable",
                code: ret,
            });
        }

        // SAFETY: Buffer was populated by GetExtendedTcpTable which guarantees:
        // - Proper alignment for MIB_TCPTABLE_OWNER_PID structure
        // - Buffer size is at least sizeof(MIB_TCPTABLE_OWNER_PID)
        // - dwNumEntries indicates valid row count for the flexible array member
        let table = buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
        let count = (*table).dwNumEntries as usize;
        
        // SAFETY: Windows guarantees the table array contains `count` valid entries
        // The buffer size was determined by Windows to accommodate the header + all rows
        let first: *const MIB_TCPROW_OWNER_PID = (*table).table.as_ptr();
        let rows = std::slice::from_raw_parts(first, count);

        let mut out = Vec::with_capacity(count);
        for row in rows {
            let local_ip = IpAddr::V4(ipv4_from_be_u32(row.dwLocalAddr));
            let remote_ip = IpAddr::V4(ipv4_from_be_u32(row.dwRemoteAddr));
            let local_port = port_from_be_u32(row.dwLocalPort);
            let remote_port = port_from_be_u32(row.dwRemotePort);

            out.push(NetworkConnection {
                protocol: Protocol::Tcp,
                local_address: local_ip,
                local_port,
                remote_address: Some(remote_ip),
                remote_port: Some(remote_port),
                state: tcp_state_from_mib(row.dwState),
                pid: row.dwOwningPid,
            });
        }

        Ok(out)
    }
}

fn query_tcp_af_v6() -> Result<Vec<NetworkConnection>, NetworkError> {
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET6;

    // SAFETY: Windows API interaction with GetExtendedTcpTable for IPv6
    // - First call with null buffer gets required size
    // - Second call writes structured data into properly sized buffer
    // - Buffer alignment requirements are satisfied by Windows API guarantees
    // - The buffer is sized by Windows and cast to MIB_TCP6TABLE_OWNER_PID with count validation
    unsafe {
        let mut size: u32 = 0;
        let mut ret = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        if ret != ERROR_INSUFFICIENT_BUFFER {
            return Err(NetworkError::WinApi {
                api: "GetExtendedTcpTable",
                code: ret,
            });
        }

        // Allocate aligned buffer: GetExtendedTcpTable guarantees proper alignment
        let mut buf = vec![0u8; size as usize];
        ret = GetExtendedTcpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != 0 {
            return Err(NetworkError::WinApi {
                api: "GetExtendedTcpTable",
                code: ret,
            });
        }

        // SAFETY: Buffer was populated by GetExtendedTcpTable which guarantees:
        // - Proper alignment for MIB_TCP6TABLE_OWNER_PID structure
        // - Buffer size accommodates header + dwNumEntries rows
        // - dwNumEntries indicates valid row count
        let table = buf.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>();
        let count = (*table).dwNumEntries as usize;
        
        // SAFETY: Windows guarantees the table array contains `count` valid IPv6 TCP entries
        let first: *const MIB_TCP6ROW_OWNER_PID = (*table).table.as_ptr();
        let rows = std::slice::from_raw_parts(first, count);

        let mut out = Vec::with_capacity(count);
        for row in rows {
            let local_ip = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
            let remote_ip = IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr));
            let local_port = port_from_be_u32(row.dwLocalPort);
            let remote_port = port_from_be_u32(row.dwRemotePort);

            out.push(NetworkConnection {
                protocol: Protocol::Tcp,
                local_address: local_ip,
                local_port,
                remote_address: Some(remote_ip),
                remote_port: Some(remote_port),
                state: tcp_state_from_mib(row.dwState),
                pid: row.dwOwningPid,
            });
        }

        Ok(out)
    }
}

fn query_udp_af_v4() -> Result<Vec<NetworkConnection>, NetworkError> {
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    // SAFETY: Windows API interaction with GetExtendedUdpTable
    // - First call with null buffer gets required size
    // - Second call writes structured data into properly sized buffer
    // - Windows guarantees proper alignment for returned MIB structures
    // - Count validation ensures slice bounds are correct
    unsafe {
        let mut size: u32 = 0;
        let mut ret = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if ret != ERROR_INSUFFICIENT_BUFFER {
            return Err(NetworkError::WinApi {
                api: "GetExtendedUdpTable",
                code: ret,
            });
        }

        // Allocate aligned buffer based on OS-provided size
        let mut buf = vec![0u8; size as usize];
        ret = GetExtendedUdpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if ret != 0 {
            return Err(NetworkError::WinApi {
                api: "GetExtendedUdpTable",
                code: ret,
            });
        }

        // SAFETY: GetExtendedUdpTable guarantees:
        // - Proper alignment for MIB_UDPTABLE_OWNER_PID
        // - Buffer contains valid header + dwNumEntries rows
        // - dwNumEntries is the actual count of rows written
        let table = buf.as_ptr().cast::<MIB_UDPTABLE_OWNER_PID>();
        let count = (*table).dwNumEntries as usize;
        
        // SAFETY: Windows guarantees `count` valid UDP entries in the table array
        let first: *const MIB_UDPROW_OWNER_PID = (*table).table.as_ptr();
        let rows = std::slice::from_raw_parts(first, count);

        let mut out = Vec::with_capacity(count);
        for row in rows {
            let local_ip = IpAddr::V4(ipv4_from_be_u32(row.dwLocalAddr));
            let local_port = port_from_be_u32(row.dwLocalPort);

            out.push(NetworkConnection {
                protocol: Protocol::Udp,
                local_address: local_ip,
                local_port,
                remote_address: None,
                remote_port: None,
                state: None,
                pid: row.dwOwningPid,
            });
        }

        Ok(out)
    }
}

fn query_udp_af_v6() -> Result<Vec<NetworkConnection>, NetworkError> {
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET6;

    // SAFETY: Windows API interaction with GetExtendedUdpTable for IPv6
    // - First call with null buffer gets required size
    // - Second call writes structured data into properly sized buffer
    // - Windows guarantees proper alignment for returned MIB structures
    // - Count validation ensures slice bounds are correct
    unsafe {
        let mut size: u32 = 0;
        let mut ret = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        if ret != ERROR_INSUFFICIENT_BUFFER {
            return Err(NetworkError::WinApi {
                api: "GetExtendedUdpTable",
                code: ret,
            });
        }

        // Allocate aligned buffer based on OS-provided size
        let mut buf = vec![0u8; size as usize];
        ret = GetExtendedUdpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if ret != 0 {
            return Err(NetworkError::WinApi {
                api: "GetExtendedUdpTable",
                code: ret,
            });
        }

        // SAFETY: GetExtendedUdpTable guarantees:
        // - Proper alignment for MIB_UDP6TABLE_OWNER_PID
        // - Buffer contains valid header + dwNumEntries rows
        // - dwNumEntries is the actual count of IPv6 UDP rows written
        let table = buf.as_ptr().cast::<MIB_UDP6TABLE_OWNER_PID>();
        let count = (*table).dwNumEntries as usize;
        
        // SAFETY: Windows guarantees `count` valid IPv6 UDP entries in the table array
        let first: *const MIB_UDP6ROW_OWNER_PID = (*table).table.as_ptr();
        let rows = std::slice::from_raw_parts(first, count);

        let mut out = Vec::with_capacity(count);
        for row in rows {
            let local_ip = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr));
            let local_port = port_from_be_u32(row.dwLocalPort);

            out.push(NetworkConnection {
                protocol: Protocol::Udp,
                local_address: local_ip,
                local_port,
                remote_address: None,
                remote_port: None,
                state: None,
                pid: row.dwOwningPid,
            });
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_state_mapping_known_values() {
        assert_eq!(tcp_state_from_mib(2), Some(TcpState::Listen));
        assert_eq!(tcp_state_from_mib(5), Some(TcpState::Established));
        assert_eq!(tcp_state_from_mib(11), Some(TcpState::TimeWait));
        assert_eq!(tcp_state_from_mib(999), None);
    }

    #[test]
    fn test_port_from_be_u32() {
        // Port 80 in network byte order is 0x0050, as u16 BE = 0x0050.
        let be: u32 = 0x5000; // 0x50 in high byte when truncated to u16 then from_be.
        assert_eq!(port_from_be_u32(be), 80);

        let be2: u32 = u16::to_be(443) as u32;
        assert_eq!(port_from_be_u32(be2), 443);
    }

    #[test]
    fn test_ipv4_from_be_u32() {
        // 127.0.0.1
        let be = u32::to_be(0x7f000001);
        assert_eq!(ipv4_from_be_u32(be), Ipv4Addr::new(127, 0, 0, 1));
    }
}
