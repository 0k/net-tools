//! Contains helpers for looking up system network interfaces.
//!
//! All public types are defined here once and have the same shape on every
//! platform. The platform-specific work of enumerating interfaces, finding the
//! default route, and locating the home router lives in the submodules below,
//! each reached through the cfg-selected `platform` alias. Conversion from the
//! `netdev` crate is confined to the `netdev_impl` module.

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr},
};

pub(crate) use ipnet::{Ipv4Net, Ipv6Net};
use n0_future::time::Instant;

use crate::ip::{LocalAddresses, is_link_local};

// Each platform module provides the same three entry points, reached through
// the `platform` alias: `get_state()`, `default_route()` and `home_router()`.
// The `netdev`-capable modules share enumeration via `netdev_impl`.
#[cfg(netdev)]
mod netdev_impl;

#[cfg(bsd)]
pub(super) mod bsd;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(posix_minimal)]
mod posix_minimal;
#[cfg(wasm_browser)]
mod wasm_browser;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(bsd)]
use self::bsd as platform;
#[cfg(any(target_os = "linux", target_os = "android"))]
use self::linux as platform;
#[cfg(posix_minimal)]
use self::posix_minimal as platform;
#[cfg(wasm_browser)]
use self::wasm_browser as platform;
#[cfg(target_os = "windows")]
use self::windows as platform;

/// The interface flag bit indicating that an interface is up.
///
/// Matches the POSIX `IFF_UP` value. On platforms that do not expose BSD-style
/// interface flags it is derived from the platform's notion of "up".
const IFF_UP: u32 = 0x1;

/// State flags for a single IPv6 address.
///
/// Hand-kept mirror of netdev's `Ipv6AddrFlags`, so the `interfaces` API is
/// identical on platforms built without `netdev` (e.g. esp-idf). All fields
/// default to `false` when the platform does not provide the information.
///
/// Flags are collected from platform-specific sources:
///
/// - **Linux/Android**: netlink `IFA_FLAGS` attribute (`IFA_F_*` from [`<linux/if_addr.h>`])
/// - **macOS/iOS/FreeBSD/OpenBSD/NetBSD**: `SIOCGIFAFLAG_IN6` ioctl (`IN6_IFF_*`)
/// - **Windows**: `NL_DAD_STATE` and `NL_SUFFIX_ORIGIN` from `IP_ADAPTER_UNICAST_ADDRESS`
///
/// [`<linux/if_addr.h>`]: https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_addr.h
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Ipv6AddrFlags {
    /// The address's preferred lifetime has expired.
    ///
    /// It stays valid for existing connections, but new connections should
    /// prefer another address.
    ///
    /// Sourced from `IFA_F_DEPRECATED` (Linux), `IN6_IFF_DEPRECATED` (BSD and
    /// macOS), or `IpDadStateDeprecated` (Windows).
    pub deprecated: bool,
    /// The address is a privacy address with a randomized interface identifier.
    ///
    /// Generated per [RFC 4941] to limit tracking, rather than derived from the
    /// interface's MAC address.
    ///
    /// Sourced from `IFA_F_TEMPORARY` (Linux), `IN6_IFF_TEMPORARY` (BSD and
    /// macOS), or `IpSuffixOriginRandom` (Windows).
    ///
    /// [RFC 4941]: https://datatracker.ietf.org/doc/html/rfc4941
    pub temporary: bool,
    /// The address is undergoing duplicate address detection.
    ///
    /// It is not yet usable: [duplicate address detection][dad] is still
    /// verifying that no other node on the link claims it.
    ///
    /// Sourced from `IFA_F_TENTATIVE` (Linux), `IN6_IFF_TENTATIVE` (BSD and
    /// macOS), or `IpDadStateTentative` (Windows).
    ///
    /// [dad]: https://datatracker.ietf.org/doc/html/rfc4862#section-5.4
    pub tentative: bool,
    /// Duplicate address detection found this address already in use.
    ///
    /// The address failed [duplicate address detection][dad]: another node on
    /// the link is already using it, so the kernel never assigned it and it
    /// cannot be used. This is the terminal counterpart to `tentative`, which
    /// marks detection still in progress.
    ///
    /// Sourced from `IFA_F_DADFAILED` (Linux), `IN6_IFF_DUPLICATED` (BSD and
    /// macOS), or `IpDadStateDuplicate` (Windows).
    ///
    /// [dad]: https://datatracker.ietf.org/doc/html/rfc4862#section-5.4
    pub duplicated: bool,
    /// The address was configured manually rather than via SLAAC.
    ///
    /// A permanent address does not expire, unlike one obtained through
    /// stateless address autoconfiguration.
    ///
    /// Sourced from `IFA_F_PERMANENT` (Linux). Not reported on BSD or Windows,
    /// where it is always `false`.
    pub permanent: bool,
}

/// An IP network on one of the machine's interfaces, either IPv4 or IPv6.
#[derive(Clone, Debug)]
pub enum IpNet {
    /// An IPv4 network.
    V4(Ipv4Net),
    /// An IPv6 network.
    V6 {
        /// The address and its network prefix.
        net: Ipv6Net,
        /// Scope ID identifying the zone of a scoped address.
        ///
        /// Holds the interface index for a link-local address, and is zero when
        /// the address is unscoped.
        scope_id: u32,
        /// Per-address state flags as reported by the OS.
        flags: Ipv6AddrFlags,
    },
}

impl PartialEq for IpNet {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (IpNet::V4(a), IpNet::V4(b)) => {
                a.addr() == b.addr()
                    && a.prefix_len() == b.prefix_len()
                    && a.netmask() == b.netmask()
            }
            (
                IpNet::V6 {
                    net: net_a,
                    scope_id: scope_id_a,
                    flags: flags_a,
                },
                IpNet::V6 {
                    net: net_b,
                    scope_id: scope_id_b,
                    flags: flags_b,
                },
            ) => {
                net_a.addr() == net_b.addr()
                    && net_a.prefix_len() == net_b.prefix_len()
                    && net_a.netmask() == net_b.netmask()
                    && scope_id_a == scope_id_b
                    && flags_a == flags_b
            }
            _ => false,
        }
    }
}
impl Eq for IpNet {}

impl IpNet {
    /// The IP address of this structure.
    pub fn addr(&self) -> IpAddr {
        match self {
            IpNet::V4(a) => IpAddr::V4(a.addr()),
            IpNet::V6 { net, .. } => IpAddr::V6(net.addr()),
        }
    }
}

/// Represents a network interface.
#[derive(Debug, Clone, derive_more::Display)]
#[display("{index}. {name} up={} addrs={addrs:?}", self.is_up())]
pub struct Interface {
    /// The interface name, such as `eth0` or `en0`.
    name: String,
    /// The OS-assigned interface index.
    index: u32,
    /// BSD-style interface flags.
    ///
    /// On platforms without real interface flags this carries only [`IFF_UP`],
    /// derived from the platform's notion of "up".
    flags: u32,
    /// The interface's hardware (MAC) address, if it has one.
    mac_addr: Option<[u8; 6]>,
    /// The IP networks assigned to the interface.
    addrs: Vec<IpNet>,
    /// Host-local container/VM plumbing (a bridge or a `veth`), see
    /// [`is_host_local_virtual`].  Decided once, when the interface is
    /// enumerated.
    host_local: bool,
}

impl PartialEq for Interface {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
            && self.name == other.name
            && self.flags == other.flags
            && self.mac_addr == other.mac_addr
    }
}

impl Eq for Interface {}

impl Interface {
    /// Is this interface up?
    pub fn is_up(&self) -> bool {
        self.flags & IFF_UP != 0
    }

    /// The name of the interface.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// A list of all ip addresses of this interface.
    pub fn addrs(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.addrs.iter().cloned()
    }

    /// Is this a host-local container/VM bridge or `veth`?
    ///
    /// Such an interface never carries a path to another host: its churn is
    /// not a major change, and its addresses are neither local addresses nor
    /// evidence of IPv4/IPv6 connectivity.
    pub fn is_host_local(&self) -> bool {
        self.host_local
    }

    /// Creates a fake interface for usage in tests.
    ///
    /// This allows tests to be independent of the host interfaces.
    pub(crate) fn fake() -> Self {
        Self {
            name: String::from("wifi0"),
            index: 2,
            flags: 69699,
            mac_addr: Some([2, 3, 4, 5, 6, 7]),
            addrs: vec![IpNet::V4(
                Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 189), 24).unwrap(),
            )],
            host_local: false,
        }
    }
}

/// Intended to store the state of the machine's network interfaces, routing table, and
/// other network configuration. For now it's pretty basic.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct State {
    /// Maps from an interface name to the interface.
    pub interfaces: HashMap<String, Interface>,
    /// List of machine's local IP addresses.
    pub local_addresses: LocalAddresses,

    /// Whether this machine has an IPv6 Global or Unique Local Address
    /// which might provide connectivity.
    pub have_v6: bool,

    /// Whether the machine has some non-localhost, non-link-local IPv4 address.
    pub have_v4: bool,

    /// Whether the current network interface is considered "expensive", which currently means LTE/etc
    /// instead of Wifi. This field is not populated by `State::new`.
    pub is_expensive: bool,

    /// The interface name for the machine's default route.
    ///
    /// It is not yet populated on all OSes.
    ///
    /// When set, its value is the map key into `interfaces`.
    pub default_route_interface: Option<String>,

    /// Monotonic timestamp, when an unsuspend was detected.
    pub last_unsuspend: Option<Instant>,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut ifaces: Vec<_> = self.interfaces.values().collect();
        ifaces.sort_by_key(|iface| iface.index);
        for iface in ifaces {
            write!(f, "{iface}")?;
            if let Some(ref default_if) = self.default_route_interface
                && iface.name() == default_if
            {
                write!(f, " (default)")?;
            }
            if f.alternate() {
                writeln!(f)?;
            } else {
                write!(f, "; ")?;
            }
        }
        Ok(())
    }
}

impl State {
    /// Returns the state of all the current machine's network interfaces.
    ///
    /// It does not set the returned `State::is_expensive`. The caller can populate that.
    pub async fn new() -> Self {
        platform::get_state().await
    }

    /// Creates a fake interface state for usage in tests.
    ///
    /// This allows tests to be independent of the host interfaces.
    pub fn fake() -> Self {
        let fake = Interface::fake();
        let ifname = fake.name().to_string();
        Self {
            interfaces: [(ifname.clone(), fake)].into_iter().collect(),
            local_addresses: LocalAddresses::default(),
            have_v6: true,
            have_v4: true,
            is_expensive: false,
            default_route_interface: Some(ifname),
            last_unsuspend: None,
        }
    }

    /// Is this a major change compared to the `old` one?.
    pub fn is_major_change(&self, old: &State) -> bool {
        if self.have_v6 != old.have_v6
            || self.have_v4 != old.have_v4
            || self.is_expensive != old.is_expensive
            || self.default_route_interface != old.default_route_interface
        {
            return true;
        }

        for (iname, i) in &old.interfaces {
            if !is_interesting_interface(i.name()) || i.is_host_local() {
                continue;
            }
            let Some(i2) = self.interfaces.get(iname) else {
                return true;
            };
            if i != i2 || !prefixes_major_equal(i.addrs(), i2.addrs()) {
                return true;
            }
        }

        // Check for new interesting interfaces not present in old state
        for (iname, i) in &self.interfaces {
            if !is_interesting_interface(i.name()) || i.is_host_local() {
                continue;
            }
            if !old.interfaces.contains_key(iname) {
                return true;
            }
        }

        false
    }
}

/// Reports whether changes to the interface named `name` are worth reacting to.
///
/// Most platforms consider every interface interesting. Apple platforms hide a
/// few virtual interfaces (AWDL, low-latency Wi-Fi, IPsec) whose churn would
/// otherwise generate spurious change events.
pub(crate) fn is_interesting_interface(name: &str) -> bool {
    #[cfg(bsd)]
    {
        let base_name = name.trim_end_matches("0123456789");
        if base_name == "llw" || base_name == "awdl" || base_name == "ipsec" {
            return false;
        }
    }
    let _ = name;
    true
}

/// Where Linux exposes one directory per network interface.
#[cfg(target_os = "linux")]
pub(crate) const SYSFS_NET: &str = "/sys/class/net";

/// Whether the interface `name` is host-local container/VM plumbing.
///
/// Docker, podman, LXC and libvirt connect containers and VMs through
/// bridges (`docker0`, `br-*`, `lxcbr0`, `virbr0`, ...) and `veth` pairs.
/// These never carry a path to another host, yet a container restarting in
/// a loop creates and deletes a `veth` (and toggles its bridge) every few
/// seconds: treating that churn as a network change makes every socket
/// rebind constantly, and advertising the bridge addresses hands remote
/// peers candidates they can never reach.
///
/// A bridge is recognised by the kernel, not by its name: it has a
/// `bridge` directory under `sysfs_net`.  A `veth` is recognised by its
/// name, which every container runtime gives it.  The interface holding the
/// default route is never host-local, so a host whose uplink is itself a
/// bridge (`br0` enslaving the NIC, common on VM hosts) keeps it.
///
/// Only recognised on Linux.
pub(crate) fn is_host_local_virtual(
    sysfs_net: &std::path::Path,
    name: &str,
    default_route: Option<&str>,
) -> bool {
    #[cfg(target_os = "linux")]
    {
        if default_route == Some(name) {
            return false;
        }
        name.starts_with("veth") || sysfs_net.join(name).join("bridge").is_dir()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (sysfs_net, name, default_route);
        false
    }
}

/// The details about a default route.
#[derive(Debug, Clone)]
pub struct DefaultRouteDetails {
    /// The interface name.
    ///
    /// It's like "eth0" (Linux), "Ethernet 2" (Windows), "en0" (macOS).
    pub interface_name: String,
}

impl DefaultRouteDetails {
    /// Reads the default route from the current system and returns the details.
    pub async fn new() -> Option<Self> {
        platform::default_route().await
    }
}

/// Like `DefaultRouteDetails::new` but only returns the interface name.
pub async fn default_route_interface() -> Option<String> {
    DefaultRouteDetails::new().await.map(|v| v.interface_name)
}

/// Likely IPs of the residential router, and the ip address of the current
/// machine using it.
#[derive(Debug, Clone)]
pub struct HomeRouter {
    /// IP of the router.
    pub gateway: IpAddr,
    /// Our local IP, if known.
    pub my_ip: Option<IpAddr>,
}

impl HomeRouter {
    /// Returns the likely IP of the residential router, which will always
    /// be a private address, if found.
    /// In addition, it returns the IP address of the current machine on
    /// the LAN using that gateway.
    /// This is used as the destination for UPnP, NAT-PMP, PCP, etc queries.
    pub fn new() -> Option<Self> {
        platform::home_router()
    }
}

/// Checks whether `a` and `b` are equal after ignoring uninteresting
/// things, like link-local, loopback and multicast addresses.
fn prefixes_major_equal(a: impl Iterator<Item = IpNet>, b: impl Iterator<Item = IpNet>) -> bool {
    fn is_interesting(p: &IpNet) -> bool {
        let a = p.addr();
        if is_link_local(a) || a.is_loopback() || a.is_multicast() {
            return false;
        }
        true
    }

    let mut a = a.filter(is_interesting);
    let mut b = b.filter(is_interesting);

    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) if a == b => continue,
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_major_change_identical() {
        let a = State::fake();
        let b = State::fake();
        assert!(!a.is_major_change(&b));
    }

    #[test]
    fn test_is_major_change_new_interface_added() {
        let old = State::fake();
        let mut new = State::fake();
        // Add a new interesting interface to new state
        let mut iface = Interface::fake();
        iface.index = 10;
        iface.name = "eth1".to_string();
        new.interfaces.insert("eth1".to_string(), iface);
        assert!(new.is_major_change(&old));
    }

    /// A copy of the fake interface renamed and re-addressed.
    fn fake_iface(name: &str, ip: Ipv4Addr, index: u32, host_local: bool) -> Interface {
        let mut iface = Interface::fake();
        iface.name = name.to_string();
        iface.index = index;
        iface.addrs = vec![IpNet::V4(Ipv4Net::new(ip, 16).unwrap())];
        iface.host_local = host_local;
        iface
    }

    fn with_iface(state: &State, iface: Interface) -> State {
        let mut state = state.clone();
        state.interfaces.insert(iface.name.clone(), iface);
        state
    }

    #[test]
    fn host_local_interface_churn_is_not_a_major_change() {
        let base = State::fake();
        let churned = with_iface(
            &base,
            fake_iface("lxcbr0", Ipv4Addr::new(10, 0, 3, 1), 9, true),
        );
        assert!(!churned.is_major_change(&base), "appeared");
        assert!(!base.is_major_change(&churned), "disappeared");
    }

    #[test]
    fn a_new_physical_interface_is_still_a_major_change() {
        let base = State::fake();
        let plugged = with_iface(
            &base,
            fake_iface("eth1", Ipv4Addr::new(10, 0, 0, 2), 9, false),
        );
        assert!(plugged.is_major_change(&base));
    }

    /// A throwaway `sysfs`-like tree: one directory per interface, with a
    /// `bridge` subdirectory for bridges.
    #[cfg(target_os = "linux")]
    struct FakeSysfs(std::path::PathBuf);

    #[cfg(target_os = "linux")]
    impl FakeSysfs {
        fn new(bridges: &[&str], others: &[&str]) -> Self {
            let root = std::env::temp_dir().join(format!(
                "netwatch-sysfs-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            for name in bridges {
                std::fs::create_dir_all(root.join(name).join("bridge")).unwrap();
            }
            for name in others {
                std::fs::create_dir_all(root.join(name)).unwrap();
            }
            Self(root)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for FakeSysfs {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bridges_are_recognised_by_the_kernel_not_by_their_name() {
        let sysfs = FakeSysfs::new(
            &["docker0", "br-a8b37eb8b48f", "lxcbr0", "virbr0", "podman0"],
            &["eth0", "wlp192s0", "wg0", "br-lan-not-a-bridge"],
        );
        for name in ["docker0", "br-a8b37eb8b48f", "lxcbr0", "virbr0", "podman0"] {
            assert!(
                is_host_local_virtual(&sysfs.0, name, Some("eth0")),
                "{name}"
            );
        }
        for name in ["eth0", "wlp192s0", "wg0", "br-lan-not-a-bridge", "missing0"] {
            assert!(
                !is_host_local_virtual(&sysfs.0, name, Some("eth0")),
                "{name}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn veth_pairs_are_host_local() {
        let sysfs = FakeSysfs::new(&[], &[]);
        assert!(is_host_local_virtual(&sysfs.0, "veth8c0b68e", Some("eth0")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_bridge_holding_the_default_route_is_kept() {
        let sysfs = FakeSysfs::new(&["br0"], &[]);
        assert!(!is_host_local_virtual(&sysfs.0, "br0", Some("br0")));
        assert!(is_host_local_virtual(&sysfs.0, "br0", Some("eth0")));
        assert!(is_host_local_virtual(&sysfs.0, "br0", None));
    }

    #[test]
    fn test_is_major_change_interface_removed() {
        let old = State::fake();
        let mut new = State::fake();
        new.interfaces.clear();
        assert!(new.is_major_change(&old));
    }

    #[tokio::test]
    async fn test_default_route() {
        let default_route = DefaultRouteDetails::new()
            .await
            .expect("missing default route");
        println!("default_route: {default_route:#?}");
    }

    #[tokio::test]
    async fn test_likely_home_router() {
        let home_router = HomeRouter::new().expect("missing home router");
        println!("home router: {home_router:#?}");
    }

    #[test]
    fn test_prefixes_major_equal() {
        use std::net::Ipv4Addr;

        let a1 = IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 1), 24).unwrap());
        let a2 = IpNet::V4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 8).unwrap());
        let a3 = IpNet::V4(Ipv4Net::new(Ipv4Addr::new(172, 16, 0, 1), 16).unwrap());

        // equal lists
        assert!(prefixes_major_equal(
            vec![a1.clone(), a2.clone()].into_iter(),
            vec![a1.clone(), a2.clone()].into_iter(),
        ));

        // both empty
        assert!(prefixes_major_equal(std::iter::empty(), std::iter::empty(),));

        // different prefixes
        assert!(!prefixes_major_equal(
            vec![a1.clone()].into_iter(),
            vec![a2.clone()].into_iter(),
        ));

        // a has extra prefix
        assert!(!prefixes_major_equal(
            vec![a1.clone(), a2.clone(), a3.clone()].into_iter(),
            vec![a1.clone(), a2.clone()].into_iter(),
        ));

        // b has extra prefix
        assert!(!prefixes_major_equal(
            vec![a1.clone(), a2.clone()].into_iter(),
            vec![a1.clone(), a2.clone(), a3.clone()].into_iter(),
        ));
    }
}
