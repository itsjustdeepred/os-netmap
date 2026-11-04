#!/usr/local/bin/python3
"""
Port scan of one device with nmap, started from the network map.

usage: scan.py start <mac> <ip> <quick|full>   start a scan in the background
       scan.py status <mac>                    the last results of this device
       scan.py list                            a summary of every scanned device
       scan.py run <mac> <ip> <profile>        (internal) the background worker

Only addresses inside a network directly attached to the firewall are
scanned, never the uplink network, the firewall itself or anything routed.
Results belong to the device, not to its address: they are kept in
/var/db/netmap/scans/<mac>.json with the last five scans, so they follow
a device whose address changes.
"""

import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

STATE_DIR = os.environ.get('NETMAP_STATE_DIR', '/var/db/netmap/scans')
MAX_RUNNING = 2
KEEP = 5  # scans kept per device
MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
PROFILES = {
    # the 200 most common TCP ports with a light service probe: about a minute
    'quick': (['-Pn', '-T4', '--top-ports', '200', '-sV', '--version-light'], 300),
    # every TCP port, service versions and an operating system guess: several minutes
    'full': (['-Pn', '-T4', '-p-', '-sV', '-O', '--osscan-limit', '--max-retries', '2'], 1800),
}


def nmap_binary():
    return shutil.which('nmap') or ('/usr/local/bin/nmap' if os.path.exists('/usr/local/bin/nmap') else None)


def path_of(key):
    return os.path.join(STATE_DIR, '%s.json' % key.replace(':', '-'))


def load(ip):
    try:
        with open(path_of(ip)) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def save(key, data):
    os.makedirs(STATE_DIR, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=STATE_DIR, prefix='.%s.' % key.replace(':', '-'))
    with os.fdopen(fd, 'w') as fh:
        json.dump(data, fh)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path_of(key))


# --------------------------------------------------------------------------
# which addresses may be scanned
# --------------------------------------------------------------------------
def default_interface():
    try:
        out = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r'interface:\s*(\S+)', out)
    return m.group(1) if m else None


def local_networks():
    """[(interface, IPv4Interface)] of every address configured on the firewall."""
    try:
        out = subprocess.run(['ifconfig', '-a'], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    nets, iface = [], None
    for line in out.splitlines():
        m = re.match(r'^(\S+):\s', line)
        if m:
            iface = m.group(1)
            continue
        m = re.search(r'\binet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)', line)
        if m and iface:
            bits = bin(int(m.group(2), 16)).count('1')
            nets.append((iface, ipaddress.ip_interface('%s/%d' % (m.group(1), bits))))
    return nets


def allowed(ip):
    """Return None when ``ip`` may be scanned, otherwise the reason it may not."""
    if os.environ.get('NETMAP_ALLOW_ANY'):  # tests only
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return 'not an IPv4 address'
    if addr.version != 4 or not addr.is_private:
        return 'only private IPv4 addresses are scanned'
    wan = default_interface()
    for iface, net in local_networks():
        if addr == net.ip:
            return 'that is the firewall itself'
        if addr in net.network and net.network.prefixlen < 31:
            if iface == wan or iface.startswith(('lo', 'wg', 'tun', 'ovpn', 'tailscale', 'enc')):
                return 'scanning the uplink or VPN networks is not allowed'
            return None
    return 'the address is not on a network attached to this firewall'


# --------------------------------------------------------------------------
# nmap XML
# --------------------------------------------------------------------------
def parse_xml(text):
    root = ET.fromstring(text)
    host = root.find('host')
    out = {'up': False, 'ports': [], 'os': [], 'mac': '', 'vendor': '', 'hostnames': [], 'closed': 0}
    if host is None:
        return out
    status = host.find('status')
    out['up'] = status is not None and status.get('state') == 'up'
    for a in host.findall('address'):
        if a.get('addrtype') == 'mac':
            out['mac'] = (a.get('addr') or '').lower()
            out['vendor'] = a.get('vendor') or ''
    out['hostnames'] = [h.get('name') for h in host.findall('hostnames/hostname') if h.get('name')]
    for p in host.findall('ports/port'):
        state = p.find('state')
        svc = p.find('service')
        if state is None or state.get('state') not in ('open', 'open|filtered'):
            continue
        s = svc.attrib if svc is not None else {}
        out['ports'].append({
            'port': int(p.get('portid')), 'proto': p.get('protocol'), 'state': state.get('state'),
            'service': s.get('name', ''), 'product': s.get('product', ''), 'version': s.get('version', ''),
            'extra': s.get('extrainfo', ''), 'tunnel': s.get('tunnel', ''), 'method': s.get('method', ''),
        })
    for extra in host.findall('ports/extraports'):
        out['closed'] += int(extra.get('count') or 0)
    for m in host.findall('os/osmatch')[:3]:
        out['os'].append({'name': m.get('name'), 'accuracy': int(m.get('accuracy') or 0)})
    run = root.find('runstats/finished')
    if run is not None:
        out['elapsed'] = float(run.get('elapsed') or 0)
    return out


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def all_records():
    if not os.path.isdir(STATE_DIR):
        return []
    out = []
    for name in sorted(os.listdir(STATE_DIR)):
        key = name[:-5].replace('-', ':')
        if name.endswith('.json') and MAC_RE.match(key):
            data = load(key)
            if data:
                out.append(data)
    return out


def running_scans():
    return sum(1 for d in all_records() if d.get('status') == 'running' and alive(d.get('pid')))


def alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, TypeError, ValueError):
        return False


def summary(entry):
    """The part of a finished scan kept in the history."""
    return {k: entry.get(k) for k in ('ip', 'profile', 'finished', 'ports', 'os', 'up', 'closed', 'elapsed', 'seen_mac')}


def start(mac, ip, profile):
    reason = allowed(ip)
    if reason:
        return {'status': 'error', 'message': reason}
    if profile not in PROFILES:
        return {'status': 'error', 'message': 'unknown scan profile'}
    if not nmap_binary():
        return {'status': 'error', 'message': 'nmap is not installed on the firewall (pkg install nmap)'}
    current = load(mac) or {}
    if current.get('status') == 'running' and alive(current.get('pid')):
        return dict(current, message='a scan of this device is already running')
    if running_scans() >= MAX_RUNNING:
        return {'status': 'error', 'message': 'two scans are already running; wait for one to finish'}
    history = list(current.get('history') or [])
    if current.get('finished') and current.get('status') == 'done':
        history.insert(0, summary(current))
    data = {'mac': mac, 'ip': ip, 'profile': profile, 'status': 'running', 'started': time.time(), 'history': history[:KEEP - 1]}
    save(mac, data)
    proc = subprocess.Popen([sys.executable, os.path.abspath(__file__), 'run', mac, ip, profile],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    data['pid'] = proc.pid
    save(mac, data)
    return data


def run(mac, ip, profile):
    args, timeout = PROFILES[profile]
    data = load(mac) or {'mac': mac, 'ip': ip, 'profile': profile, 'started': time.time(), 'history': []}
    data.update({'status': 'running', 'pid': os.getpid()})
    save(mac, data)
    fd, xml_path = tempfile.mkstemp(dir=STATE_DIR, prefix='.scan.', suffix='.xml')
    os.close(fd)
    cmd = [nmap_binary()] + args + ['-oX', xml_path, ip]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=timeout)
        with open(xml_path) as fh:
            text = fh.read()
        if not text.strip():
            raise ValueError((proc.stderr or 'nmap produced no output').strip()[-300:])
        result = parse_xml(text)
        # the address may have moved to another device since the scan was asked for
        result['seen_mac'] = result.pop('mac', '')
        data.update(result)
        data.update({'status': 'done', 'finished': time.time()})
    except subprocess.TimeoutExpired:
        data.update({'status': 'error', 'message': 'the scan took longer than %d minutes' % (timeout // 60),
                     'finished': time.time()})
    except (OSError, ValueError, ET.ParseError) as exc:
        data.update({'status': 'error', 'message': str(exc), 'finished': time.time()})
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass
    data.pop('pid', None)
    data['command'] = ' '.join(['nmap'] + args + [ip])
    save(mac, data)


def status(mac):
    data = load(mac)
    if not data:
        return {'status': 'none', 'mac': mac}
    if data.get('status') == 'running' and not alive(data.get('pid')):
        data.update({'status': 'error', 'message': 'the scan stopped unexpectedly'})
    data.pop('pid', None)
    return data


def listing():
    out = []
    for d in all_records():
        last = d if d.get('status') == 'done' else ((d.get('history') or [None])[0] or {})
        out.append({'mac': d.get('mac'), 'ip': last.get('ip') or d.get('ip'), 'status': d.get('status'),
                    'finished': last.get('finished'),
                    'open': [{'port': p['port'], 'proto': p['proto'], 'service': p.get('service', '')}
                             for p in last.get('ports') or []]})
    return {'status': 'ok', 'devices': out}


def main():
    args = sys.argv[1:]
    action = args[0] if args else ''
    if action == 'list':
        print(json.dumps(listing()))
        return 0
    mac = (args[1] if len(args) > 1 else '').lower()
    if not MAC_RE.match(mac):
        print(json.dumps({'status': 'error', 'message': 'invalid MAC address'}))
        return 0
    if action in ('start', 'run'):
        ip = args[2] if len(args) > 2 else ''
        profile = args[3] if len(args) > 3 else 'quick'
        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            print(json.dumps({'status': 'error', 'message': 'invalid address'}))
            return 0
        if action == 'run':
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            run(mac, ip, profile)
            return 0
        out = start(mac, ip, profile)
    elif action == 'status':
        out = status(mac)
    else:
        out = {'status': 'error', 'message': 'unknown action'}
    print(json.dumps(out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
