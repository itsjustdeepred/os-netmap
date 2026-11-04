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

Then open **Reporting > Network Map**. `uninstall.sh` removes the files.

## License

BSD 2-Clause, see LICENSE.
