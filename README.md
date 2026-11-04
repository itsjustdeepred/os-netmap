# os-netmap

Network Map for OPNsense: every device on the networks of the firewall, how
it is connected, how much it talks right now and what the firewall does
with its traffic. Read-only.

## What it shows

The page is under **Network Map > Dashboard** in the main menu.

* **Networks view** – the firewall on top and one panel per network (VLAN)
  with a card for every device: kind (camera, phone, printer, smart home,
  ...), name, address, cable or Wi-Fi, live traffic and packets blocked by
  the firewall. Filters: networks, cable / Wi-Fi, kind, talking now,
  offline devices, search by name, IP, MAC or maker.
* **Physical view** – with the
  [Instant On plugin](https://github.com/itsjustdeepred/os-instanton): the
  tree from the firewall to switches and access points, with port, speed,
  PoE power and Wi-Fi signal of every link.
* **Device panel** (click a card) – live traffic chart, every open
  connection with the remote host named from the DNS cache, port, rate,
  bytes and the rule that allowed it, and the packets the firewall blocked
  with the rule that blocked them.

* **Name, kind and DHCP** (device panel) – rename a device, choose its kind
  and add notes (stored in the firewall configuration, also for devices
  outside DHCP). See whether Kea DHCP has a reservation for it; edit its
  address, hostname and description, delete it, or reserve the current
  address, then apply the change to Kea. Reservation changes use the Kea
  API with the privileges of the logged-in user. Device names come from,
  in order: the name given in the map, the Kea reservation, Instant On,
  the DHCP lease and the ARP table.
* **Firewall** (device panel) – *Ban* blocks every packet the device sends
  through the firewall (Internet, other networks, services of the firewall);
  *Block Internet* keeps it on the local networks. Both use MAC address
  aliases (`netmap_banned`, `netmap_nowan`), so the block follows the device
  when its address changes; the two block rules ("Network Map: ...") are
  created on every internal network the first time they are needed and
  applied. *Port forwards* to the device are
  listed and can be added (WAN address, protocol, port or range, device
  port) or deleted. The **Restrictions** button lists blocked devices and
  every port forward. These changes use the firewall API with the
  privileges of the logged-in user.
* **Firewall rules for this device** (device panel) – the rules on the
  device's interface whose source covers it (any, its network, its address
  or an alias holding its address or MAC address), and the rules elsewhere
  that name it as destination, in evaluation order, with the open
  connections and recent blocks of each. A switch enables or disables a
  rule (after a confirmation; applied at once); the name opens the rule in
  Firewall > Rules. Rules whose aliases cannot be resolved here (GeoIP,
  URL tables, host names) are marked *may apply*.
* **New devices** – after a one-time approval of the devices already on
  the network, every device that joins for the first time is marked *new*
  until it is approved or banned; the *New* button shows only those.
* **Groups** – a device can belong to a group (Kids, Untrusted IoT, ...);
  the map filters by group and blocks or allows Internet access for all
  the devices of a group at once.
* **Internet on a schedule** – block Internet access during a schedule of
  Firewall > Settings > Schedules (one alias and one scheduled rule per
  schedule, created when first used).
* **Wake-on-LAN** – a *Wake* button in the device panel (needs os-wol).
* **History** – traffic of the device over the last 24 hours, 7 or 30
  days from Insight (NetFlow), with the remote hosts it talked to most.
* **Icon** – the kind of a device, and so its icon, can be chosen from a
  grid in the rename form.
* **Open ports** (device panel) – a Fing-like port scan with nmap running
  on the firewall: *quick* (the 200 most common TCP ports with service
  names, about a minute) or *full* (every TCP port, service versions and an
  operating system guess). Web interfaces get an *open* link; ports that
  were not open in the previous scan are marked *new*. Only devices on the
  networks attached to the firewall can be scanned, never the uplink
  network, VPNs or the firewall itself; at most two scans run at a time.
  Starting scans needs the privilege *Reporting: Network Map: scan devices*.

## Where the data comes from

Only core OPNsense APIs, read from the browser:

| Data | API |
|---|---|
| Networks | `interfaces/overview/interfaces_info` |
| Devices | `hostdiscovery/service/search`, `kea/leases4/search`, `diagnostics/interface/get_arp` |
| Live traffic | `diagnostics/firewall/query_states` (bytes per direction; rates from the change between polls) |
| Blocked packets | `diagnostics/firewall/log` |
| Remote names | `unbound/diagnostics/dumpcache` |
| Physical links, Wi-Fi | `instanton/status/{clients,topology}` (optional) |
| Open ports | `netmap/scan/{start,status}` (this plugin, nmap) |
| Names, kinds, notes | `netmap/devices/{list,save}` (this plugin) |
| Bans, Internet block | `firewall/alias/{search,add,set}_item`, `firewall/alias/reconfigure`, `firewall/filter/{search,add}_rule`, `firewall/filter/apply` |
| Rules of a device | `firewall/filter/search_rule`, `firewall/filter/toggle_rule`, `firewall/filter/apply`, `firewall/alias/search_item` |
| Wake-on-LAN | `wol/wol/set` (os-wol) |
| History | `diagnostics/networkinsight/top/FlowSourceAddrDetails` |
| Port forwards | `firewall/d_nat/{search,add,del}_rule`, `firewall/d_nat/apply` |
| DHCP reservations | `kea/dhcpv4/{search,add,set,del}_reservation`, `kea/dhcpv4/search_subnet`, `kea/service/reconfigure` |

Limits: the firewall only sees traffic that crosses it (to the Internet
and between networks). Two devices on the same network talk through the
switch and their traffic is not counted. Blocked packets appear only for
rules with logging enabled and for the default block rules. Without the
Instant On plugin the map does not show cable or Wi-Fi: the firewall cannot
see how a device reaches the switch.

The ACL *Reporting: Network Map* grants the page and read access to the
APIs above.

## Installation

Copy this repository to the firewall and run as root:

```sh
sh install.sh
```

`install.sh` also installs `nmap` from the OPNsense package repository
when it is missing. Then open **Network Map > Dashboard**. `uninstall.sh` removes the files.

## License

BSD 2-Clause, see LICENSE.
