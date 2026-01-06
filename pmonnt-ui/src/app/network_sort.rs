use std::net::IpAddr;

use pmonnt_core::network::{NetworkConnection, Protocol, TcpState};

type IpKey = (u8, [u8; 16]);
type RemoteKey = (u8, IpKey, u16);
type StableKey = (u8, IpKey, u16, RemoteKey, u8, u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum NetworkSortKey {
    #[default]
    Protocol,
    Local,
    Remote,
    State,
    Pid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NetworkSortState {
    pub(crate) key: NetworkSortKey,
    pub(crate) ascending: bool,
}

impl Default for NetworkSortState {
    fn default() -> Self {
        Self {
            key: NetworkSortKey::Protocol,
            ascending: true,
        }
    }
}

impl NetworkSortState {
    pub(crate) fn toggle_or_set(&mut self, key: NetworkSortKey) {
        if self.key == key {
            self.ascending = !self.ascending;
        } else {
            self.key = key;
            self.ascending = true;
        }
    }
}

fn ip_key(ip: IpAddr) -> IpKey {
    match ip {
        IpAddr::V4(v4) => {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&v4.octets());
            (0, b)
        }
        IpAddr::V6(v6) => (1, v6.octets()),
    }
}

fn proto_key(p: Protocol) -> u8 {
    match p {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
    }
}

fn state_key(s: Option<TcpState>) -> u8 {
    match s {
        None => 255,
        Some(TcpState::Listen) => 0,
        Some(TcpState::Established) => 1,
        Some(TcpState::SynSent) => 2,
        Some(TcpState::SynReceived) => 3,
        Some(TcpState::FinWait1) => 4,
        Some(TcpState::FinWait2) => 5,
        Some(TcpState::CloseWait) => 6,
        Some(TcpState::Closing) => 7,
        Some(TcpState::LastAck) => 8,
        Some(TcpState::TimeWait) => 9,
        Some(TcpState::DeleteTcb) => 10,
        Some(TcpState::Closed) => 11,
    }
}

fn remote_key(c: &NetworkConnection) -> RemoteKey {
    // Put "no remote" last.
    match (c.remote_address, c.remote_port) {
        (Some(ip), Some(port)) => (0, ip_key(ip), port),
        _ => (1, (2, [0u8; 16]), u16::MAX),
    }
}

fn stable_key(c: &NetworkConnection) -> StableKey {
    (
        proto_key(c.protocol),
        ip_key(c.local_address),
        c.local_port,
        remote_key(c),
        state_key(c.state),
        c.pid,
    )
}

pub(crate) fn sort_connections(conns: &mut [NetworkConnection], sort: NetworkSortState) {
    conns.sort_by(|a, b| {
        let ord = match sort.key {
            NetworkSortKey::Protocol => {
                (proto_key(a.protocol), stable_key(a)).cmp(&(proto_key(b.protocol), stable_key(b)))
            }
            NetworkSortKey::Local => ((ip_key(a.local_address), a.local_port), stable_key(a))
                .cmp(&((ip_key(b.local_address), b.local_port), stable_key(b))),
            NetworkSortKey::Remote => {
                (remote_key(a), stable_key(a)).cmp(&(remote_key(b), stable_key(b)))
            }
            NetworkSortKey::State => {
                (state_key(a.state), stable_key(a)).cmp(&(state_key(b.state), stable_key(b)))
            }
            NetworkSortKey::Pid => (a.pid, stable_key(a)).cmp(&(b.pid, stable_key(b))),
        };

        if sort.ascending {
            ord
        } else {
            ord.reverse()
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn conn(
        protocol: Protocol,
        local: IpAddr,
        local_port: u16,
        remote: Option<IpAddr>,
        remote_port: Option<u16>,
        state: Option<TcpState>,
        pid: u32,
    ) -> NetworkConnection {
        NetworkConnection {
            protocol,
            local_address: local,
            local_port,
            remote_address: remote,
            remote_port,
            state,
            pid,
        }
    }

    #[test]
    fn toggle_or_set_flips_and_resets() {
        let mut s = NetworkSortState::default();
        assert_eq!(s.key, NetworkSortKey::Protocol);
        assert!(s.ascending);

        s.toggle_or_set(NetworkSortKey::Protocol);
        assert_eq!(s.key, NetworkSortKey::Protocol);
        assert!(!s.ascending);

        s.toggle_or_set(NetworkSortKey::Remote);
        assert_eq!(s.key, NetworkSortKey::Remote);
        assert!(s.ascending);
    }

    #[test]
    fn remote_none_sorts_last_in_remote_ascending() {
        let local = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let remote = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let mut conns = vec![
            conn(
                Protocol::Tcp,
                local,
                5000,
                None,
                None,
                Some(TcpState::Established),
                10,
            ),
            conn(
                Protocol::Tcp,
                local,
                5001,
                Some(remote),
                Some(443),
                Some(TcpState::Established),
                11,
            ),
        ];

        sort_connections(
            &mut conns,
            NetworkSortState {
                key: NetworkSortKey::Remote,
                ascending: true,
            },
        );

        assert!(conns[0].remote_address.is_some());
        assert!(conns[1].remote_address.is_none());
    }

    #[test]
    fn stable_tie_breaker_makes_sort_deterministic() {
        let local_v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let local_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let remote_a = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let remote_b = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));

        // All share the same primary sort key (State: Established), so ordering must be stable.
        let mut conns = vec![
            conn(
                Protocol::Udp,
                local_v4,
                53,
                Some(remote_b),
                Some(53),
                Some(TcpState::Established),
                200,
            ),
            conn(
                Protocol::Tcp,
                local_v6,
                1234,
                Some(remote_a),
                Some(443),
                Some(TcpState::Established),
                100,
            ),
            conn(
                Protocol::Tcp,
                local_v4,
                80,
                None,
                None,
                Some(TcpState::Established),
                150,
            ),
        ];

        let mut expected = conns.clone();
        expected.sort_by_key(stable_key);

        sort_connections(
            &mut conns,
            NetworkSortState {
                key: NetworkSortKey::State,
                ascending: true,
            },
        );

        assert_eq!(
            conns.iter().map(stable_key).collect::<Vec<_>>(),
            expected.iter().map(stable_key).collect::<Vec<_>>()
        );
    }

    #[test]
    fn sort_by_protocol_ascending_and_descending() {
        let local = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut conns = vec![
            conn(Protocol::Udp, local, 5000, None, None, None, 1),
            conn(Protocol::Tcp, local, 5001, None, None, None, 2),
        ];

        sort_connections(
            &mut conns,
            NetworkSortState {
                key: NetworkSortKey::Protocol,
                ascending: true,
            },
        );
        assert_eq!(conns[0].protocol, Protocol::Tcp);

        sort_connections(
            &mut conns,
            NetworkSortState {
                key: NetworkSortKey::Protocol,
                ascending: false,
            },
        );
        assert_eq!(conns[0].protocol, Protocol::Udp);
    }

    #[test]
    fn sort_by_local_ascending_and_descending() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut conns = vec![
            conn(Protocol::Tcp, b, 80, None, None, None, 1),
            conn(Protocol::Tcp, a, 443, None, None, None, 2),
        ];

        sort_connections(
            &mut conns,
            NetworkSortState {
                key: NetworkSortKey::Local,
                ascending: true,
            },
        );
        assert_eq!(conns[0].local_address, a);

        sort_connections(
            &mut conns,
            NetworkSortState {
                key: NetworkSortKey::Local,
                ascending: false,
            },
        );
        assert_eq!(conns[0].local_address, b);
    }

    #[test]
    fn sort_by_pid_ascending_and_descending() {
        let local = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut conns = vec![
            conn(Protocol::Tcp, local, 1000, None, None, None, 10),
            conn(Protocol::Tcp, local, 1001, None, None, None, 5),
        ];

        sort_connections(
            &mut conns,
            NetworkSortState {
                key: NetworkSortKey::Pid,
                ascending: true,
            },
        );
        assert_eq!(conns[0].pid, 5);

        sort_connections(
            &mut conns,
            NetworkSortState {
                key: NetworkSortKey::Pid,
                ascending: false,
            },
        );
        assert_eq!(conns[0].pid, 10);
    }

    #[test]
    fn ipv4_ipv6_mixed_is_deterministic_and_no_panic() {
        let local_v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let local_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mut conns = vec![
            conn(Protocol::Tcp, local_v6, 80, None, None, None, 1),
            conn(Protocol::Tcp, local_v4, 80, None, None, None, 2),
        ];

        // Should not panic and should produce deterministic output
        let mut expected = conns.clone();
        expected.sort_by(|a, b| {
            ((ip_key(a.local_address), a.local_port), stable_key(a))
                .cmp(&((ip_key(b.local_address), b.local_port), stable_key(b)))
        });

        sort_connections(
            &mut conns,
            NetworkSortState {
                key: NetworkSortKey::Local,
                ascending: true,
            },
        );

        assert_eq!(
            conns
                .iter()
                .map(|c| ((ip_key(c.local_address), c.local_port), stable_key(c)))
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|c| ((ip_key(c.local_address), c.local_port), stable_key(c)))
                .collect::<Vec<_>>()
        );
    }
}
