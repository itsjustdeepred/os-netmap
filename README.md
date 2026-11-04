# os-netmap

Network Map for OPNsense: every device on the networks of the firewall, how
it is connected, how much it talks right now and what the firewall does
with its traffic. Read-only.

## What it shows

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
| DHCP reservations | `kea/dhcpv4/{search,add,set,del}_reservation`, `kea/dhcpv4/search_subnet`, `kea/service/reconfigure` |

Limits: the firewall only sees traffic that crosses it (to the Internet
and between networks). Two devices on the same network talk through the
switch and their traffic is not counted. Blocked packets appear only for
rules with logging enabled and for the default block rules. Without the
Instant On plugin, cable or Wi-Fi is a guess (private MAC addresses and
mobile devices are taken as Wi-Fi) and shown faded.

The ACL *Reporting: Network Map* grants the page and read access to the
APIs above.

## Installation

Copy this repository to the firewall and run as root:

```sh
sh install.sh
```

`install.sh` also installs `nmap` from the OPNsense package repository
when it is missing. Then open **Reporting > Network Map**. `uninstall.sh` removes the files.

## License

BSD 2-Clause, see LICENSE.
