"""Offline tests of the port scan backend: nmap XML parsing and the address check."""

import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src', 'opnsense', 'scripts', 'netmap'))

import scan  # noqa: E402

XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<address addr="10.0.20.50" addrtype="ipv4"/><address addr="AA:BB:CC:00:11:22" addrtype="mac" vendor="Espressif"/>
<hostnames><hostname name="plug.lan" type="PTR"/></hostnames>
<ports><extraports state="closed" count="197"/>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="lighttpd" version="1.4" method="probed"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl" product="nginx"/></port>
<port protocol="tcp" portid="8081"><state state="closed"/><service name="blackice-icecap"/></port>
</ports>
<os><osmatch name="Linux 4.x" accuracy="96"/><osmatch name="Linux 5.x" accuracy="90"/></os>
</host><runstats><finished elapsed="12.5"/></runstats></nmaprun>"""

IFCONFIG = """igc0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
\tinet 192.168.1.186 netmask 0xffffff00 broadcast 192.168.1.255
vlan0.20: flags=8863<UP> metric 0 mtu 1500
\tinet 10.0.20.1 netmask 0xffffff00 broadcast 10.0.20.255
wg1: flags=8051<UP> metric 0 mtu 1420
\tinet 10.2.0.2 netmask 0xffffffff
"""


class ParseTest(unittest.TestCase):
    def test_parse(self):
        r = scan.parse_xml(XML)
        self.assertTrue(r['up'])
        self.assertEqual(r['mac'], 'aa:bb:cc:00:11:22')
        self.assertEqual([p['port'] for p in r['ports']], [80, 443])  # closed ports are left out
        self.assertEqual(r['ports'][1]['tunnel'], 'ssl')
        self.assertEqual(r['closed'], 197)
        self.assertEqual(r['os'][0], {'name': 'Linux 4.x', 'accuracy': 96})
        self.assertEqual(r['hostnames'], ['plug.lan'])


class AllowedTest(unittest.TestCase):
    def setUp(self):
        os.environ.pop('NETMAP_ALLOW_ANY', None)
        run = mock.Mock(side_effect=lambda cmd, **kw: mock.Mock(
            stdout=IFCONFIG if cmd[0] == 'ifconfig' else 'interface: igc0\n'))
        self.patch = mock.patch.object(scan.subprocess, 'run', run)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()

    def test_lan_device_allowed(self):
        self.assertIsNone(scan.allowed('10.0.20.50'))

    def test_refused(self):
        self.assertIn('uplink', scan.allowed('192.168.1.10'))       # provider network
        self.assertIn('firewall itself', scan.allowed('10.0.20.1'))
        self.assertIn('not on a network', scan.allowed('10.9.9.9'))
        self.assertIn('private', scan.allowed('8.8.8.8'))
        self.assertIn('not an IPv4', scan.allowed('nonsense'))


if __name__ == '__main__':
    unittest.main()
