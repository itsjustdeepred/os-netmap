/*
 * Network Map for OPNsense.
 * Copyright (C) 2026 os-netmap contributors. BSD 2-Clause license.
 *
 * Built only from read-only core APIs (interfaces, host discovery, Kea
 * leases, ARP, state table, firewall log, Unbound cache) plus the Instant On
 * plugin when it is installed (physical topology, Wi-Fi details).
 */
(function (window, $) {
    'use strict';

    var API = window.NetmapApiBase || '/api/';
    var EVERY = {states: 10, log: 30, hosts: 120, dns: 300, live: 3};
    var HISTORY = 40;  // samples kept for the live chart

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------
    function esc(v) {
        return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, function (c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
        });
    }

    function icon(name, title) {
        return '<i class="fa fa-' + name + '"' + (title ? ' title="' + esc(title) + '"' : '') + ' aria-hidden="true"></i>';
    }

    function bytes(n) {
        if (!n) { return '0 B'; }
        var u = ['B', 'kB', 'MB', 'GB', 'TB'], i = 0;
        while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
        return (n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)) + ' ' + u[i];
    }

    function rate(bps) {
        if (!bps || bps < 1) { return '0'; }
        var u = ['b/s', 'kb/s', 'Mb/s', 'Gb/s'], i = 0;
        while (bps >= 1000 && i < u.length - 1) { bps /= 1000; i++; }
        return (bps >= 100 || i === 0 ? Math.round(bps) : bps.toFixed(1)) + ' ' + u[i];
    }

    function ago(ts) {
        if (!ts) { return ''; }
        var s = Math.max(0, Math.round(Date.now() / 1000 - ts));
        if (s < 60) { return s + ' s ago'; }
        if (s < 3600) { return Math.round(s / 60) + ' min ago'; }
        if (s < 86400) { return Math.round(s / 3600) + ' h ago'; }
        return Math.round(s / 86400) + ' d ago';
    }

    function get(path) {
        // global: false keeps the OPNsense error dialog away for optional sources (Instant On, Kea)
        return $.ajax({url: API + path, type: 'GET', dataType: 'json', cache: false, global: false});
    }

    function search(path, body) {
        return $.ajax({url: API + path, type: 'POST', dataType: 'json', contentType: 'application/json', global: false,
            data: JSON.stringify(body || {current: 1, rowCount: -1, searchPhrase: ''})});
    }

    // the live log page applies one filter given in the URL hash
    function logLink(field, value) {
        return '/ui/diagnostics/firewall/log#field=' + encodeURIComponent(field) + '&operator=' + encodeURIComponent('=') +
            '&value=' + encodeURIComponent(value);
    }

    // IP protocol numbers and well-known ports, for flows reported as numbers (Insight / NetFlow)
    var PROTOCOLS = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 58: 'ICMPv6', 89: 'OSPF', 112: 'VRRP'};
    var SERVICES = {20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP',
        110: 'POP3', 123: 'NTP', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS',
        445: 'SMB', 465: 'SMTPS', 514: 'syslog', 554: 'RTSP', 587: 'SMTP', 853: 'DNS over TLS', 993: 'IMAPS', 995: 'POP3S',
        1883: 'MQTT', 1900: 'SSDP', 3389: 'RDP', 3478: 'STUN', 4007: '', 5000: '', 5353: 'mDNS', 5683: 'CoAP', 8008: 'HTTP',
        8080: 'HTTP', 8443: 'HTTPS', 8883: 'MQTT TLS', 8000: 'HTTP', 51820: 'WireGuard'};

    function protoName(p) {
        var n = String(p || '');
        return (/^\d+$/.test(n) ? PROTOCOLS[+n] || 'proto ' + n : n.toUpperCase());
    }

    function portLabel(proto, port) {
        var svc = port ? SERVICES[+port] : '';
        return protoName(proto) + (port ? ' ' + port : '') + (svc ? ' · ' + svc : '');
    }

    function ipNum(ip) {
        var p = String(ip).split('.');
        return p.length === 4 ? ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + (+p[3]) : null;
    }

    function inCidr(ip, cidr) {
        var parts = String(cidr || '').split('/');
        var a = ipNum(ip), n = ipNum(parts[0]), bits = +parts[1];
        if (a === null || n === null || !(bits >= 0 && bits <= 32)) { return false; }
        var mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
        return ((a & mask) >>> 0) === ((n & mask) >>> 0);
    }

    function normMac(mac) { return String(mac || '').toLowerCase(); }

    function isRandomMac(mac) {
        var first = parseInt(String(mac).slice(0, 2), 16);
        return !isNaN(first) && (first & 2) === 2;
    }

    // ------------------------------------------------------------------
    // device kinds (same rules as the Instant On plugin)
    // ------------------------------------------------------------------
    var TYPES = {
        router: ['Router / gateway', 'globe'], firewall: ['Firewall', 'shield'], 'switch': ['Switch', 'sitemap'],
        ap: ['Access point', 'wifi'], network: ['Network device', 'random'], server: ['Server', 'server'],
        vm: ['Virtual machine', 'cubes'], nas: ['NAS / storage', 'hdd-o'], computer: ['Computer', 'desktop'],
        laptop: ['Laptop', 'laptop'], phone: ['Phone', 'mobile'], tablet: ['Tablet', 'tablet'], watch: ['Watch', 'clock-o'],
        tv: ['TV', 'television'], media: ['Media player', 'play-circle'], speaker: ['Speaker', 'volume-up'],
        console: ['Game console', 'gamepad'], printer: ['Printer', 'print'], camera: ['Camera', 'video-camera'],
        nvr: ['Video recorder', 'film'], intercom: ['Intercom / doorbell', 'bell'], alarm: ['Alarm system', 'lock'],
        voip: ['VoIP phone', 'phone'], iot: ['Smart home', 'house-signal'], climate: ['Climate / heating', 'temperature-half'],
        appliance: ['Appliance', 'kitchen-set'], ev: ['EV charger', 'charging-station'], power: ['UPS / power', 'car-battery'],
        washer: ['Washing machine', 'jug-detergent'], dryer: ['Dryer', 'shirt'], dishwasher: ['Dishwasher', 'soap'],
        fridge: ['Fridge / freezer', 'snowflake'], oven: ['Oven / cooktop', 'fire-burner'], coffee: ['Coffee machine', 'mug-hot'],
        vacuum: ['Robot (vacuum, mower)', 'robot'], solar: ['Inverter / solar', 'solar-panel'], plug: ['Smart plug / relay', 'plug'],
        light: ['Light', 'lightbulb'], sensor: ['Sensor', 'temperature-low'], fan: ['Fan / air purifier', 'fan'],
        unknown: ['Unknown', 'question']
    };
    // common device names in several languages; the more specific kinds first
    var NAME_RULES = [
        ['ap', /access ?point|^ap\b|\bap$/],
        // brands first: "camera" is also the Italian word for bedroom ("sonos camera")
        ['speaker', /sonos|homepod|\becho (dot|show|studio)\b/],
        ['intercom', /intercom|citofono|videocitofono|interphone|door ?station|doorbell|campanello|sprechanlage/],
        ['nvr', /\bnvr\b|\bdvr\b|recorder|videoregistratore/],
        ['camera', /\bcam\b|camera|telecamera|\bipcam|webcam|kamera|cam\d|\btapo c\d+|^c(100|110|200|210|220|310|320|500)$/],
        ['alarm', /alarm|allarme|centrale|alarmanlage/],
        ['plug', /shelly|sonoff|tasmota|\bkasa\b|tapo p\d+|smart ?plug|\bplug\b|presa|relay|\brele\b/],
        ['iot', /esphome|\besp(32|8266)?\b|tuya/],
        ['printer', /print|stampante|drucker|imprimante|laserjet|officejet|deskjet|\bbrw|\bepson|bambu|prusa|\bmfc/],
        ['nas', /\bnas\b|synology|diskstation|qnap|truenas|readynas/],
        ['server', /server|proxmox|\bpve\b|esxi|jellyfin|plex|home ?assistant|hassio|unraid|docker|\bnuc\b/],
        ['vm', /\bvm\b|virtual/],
        ['tablet', /ipad|\btab\b|tablet|galaxy ?tab|kindle|fire ?hd/],
        ['watch', /watch|orologio/],
        ['phone', /iphone|android|galaxy|pixel|redmi|oneplus|xiaomi|\bs\d{2}\b|ultra|phone|telefono|cellulare|handy/],
        ['laptop', /macbook|laptop|notebook|thinkpad|ideapad|\bxps\b|surface|chromebook/],
        ['tv', /\btv\b|televisio|televisore|fernseher|bravia|webos|tizen|smart ?tv/],
        ['media', /chromecast|apple ?tv|\broku\b|fire ?tv|shield|media ?player|kodi|appletv/],
        ['speaker', /sonos|\bzp\b|sonoszp|echo|alexa|homepod|google ?home|nest ?(mini|audio|hub)|speaker|soundbar|cassa/],
        ['console', /playstation|\bps[345]\b|xbox|nintendo/],
        ['voip', /voip|\bsip\b|yealink|snom|gigaset|grandstream|polycom/],
        ['ev', /wallbox|charger|easee|zaptec|colonnina|ladestation/],
        ['climate', /air ?condition|\bac\b|climat|condizionat|thermostat|termostato|heat ?pump|pompa di calore|caldaia|boiler|daikin|tado|netatmo|\bhvac\b/],
        ['dishwasher', /lavastoviglie|dishwasher|geschirrsp/],
        ['washer', /lavatrice|washer|washing|waschmaschine|lave linge/],
        ['dryer', /asciugatrice|dryer|trockner|seche linge/],
        ['fridge', /frigo|fridge|refrigerator|freezer|congelatore|k.hlschrank|cantinetta/],
        ['oven', /forno|\boven\b|cooktop|piano cottura|induction|induzione|\bhob\b|microwave|microonde|\bhood\b|cappa/],
        ['coffee', /coffee|caffe|caff\u00e8|espresso|nespresso|kaffee/],
        ['vacuum', /roborock|roomba|vacuum|aspirapolvere|robot|dreame|ecovacs|deebot|navimow|mower|tosaerba|rasaerba|automower/],
        ['solar', /inverter|solar|fotovoltaico|photovoltaic|\bpv\b|zendure|huawei smartgrid|smartgrid|battery|batteria/],
        ['fan', /\bfan\b|ventilat|purifier|purificatore/],
        ['appliance', /miele|\bneff\b|bosch|siemens|appliance|elettrodomestic/],
        ['power', /\bups\b|\bpdu\b/],
        ['light', /\bled\b|lamp|lampada|\bluce\b|\bluci\b|light|\bhue\b|dimmer|rgbw|strip/],
        ['sensor', /sensor|sensore|presence|motion|weather|meteo|ecowitt|weatherflow|termometro|thermometer|humidity/],
        ['iot', /zigbee|z-?wave|gateway|bridge|domotic|smart|vimar|bticino|irrigat|garage|gate|cancello/],
        ['firewall', /opnsense|pfsense|firewall/],
        ['router', /router|fritz|modem|\bont\b/],
        ['ap', /access ?point|\bap\b/],
        ['switch', /\bswitch\b/],
        ['network', /mesh|repeater|extender|ripetitore/],
        ['computer', /imac|desktop|\bpc\b|workstation|computer|mac ?mini|mac ?studio|raspberry|\brpi\b/]
    ];
    var VENDOR_RULES = [
        ['camera', /hikvision|dahua|axis communications|hanwha|uniview|reolink|amcrest|foscam|ezviz|imou|mobotix|vivotek/i],
        ['nas', /synology|qnap|western digital|asustor|terramaster|buffalo/i],
        ['speaker', /sonos|bose|denon|bang & olufsen|harman|bluesound|marantz/i],
        ['plug', /shelly|allterco|itead/i],
        ['light', /signify|philips lighting|lifx|nanoleaf/i],
        ['vacuum', /irobot|roborock|dreame|ecovacs|segway/i],
        ['iot', /espressif|tuya|lumi united|aqara|ecobee|netatmo|weatherflow|laird|vimar|bticino|legrand|silicon labs|nordic semiconductor|texas instruments|murata|azurewave|seongji|sji industry|chongqing fugui|meross|wiz connected|wistron neweb|universal global scientific|hui zhou gaoshengda/i],
        ['climate', /daikin|tado|mitsubishi electric|gree electric|midea|viessmann|vaillant/i],
        ['appliance', /miele|bsh hausger|electrolux|whirlpool|haier|candy|smeg|liebherr|irobot|roborock|dreame|ecovacs/i],
        ['printer', /brother|canon|seiko epson|lexmark|kyocera|ricoh|xerox|konica|zebra|bambu/i],
        ['vm', /proxmox|vmware|qemu|xensource|parallels/i],
        ['computer', /intel corporate|elitegroup|giga-byte|asustek|micro-star|asrock|dell|lenovo|wistron corp|quanta|compal|liteon|raspberry pi|pegatron|super micro/i],
        ['alarm', /tecnoalarm|ajax systems|paradox|bentel|inim|risco|digital security controls|honeywell security/i],
        ['intercom', /2n telecom|fermax|comelit|urmet|doorbird|akuvox/i],
        ['voip', /yealink|snom|polycom|grandstream|gigaset|fanvil|avaya|mitel/i],
        ['console', /nintendo|sony interactive|valve/i],
        ['media', /roku|nvidia/i],
        ['ev', /wallbox|easee|zaptec|tesla|enphase|alfen/i],
        ['power', /american power conversion|schneider|eaton|delta electronics|cyber power|riello|vertiv|sma solar|fronius|solaredge/i],
        ['firewall', /deciso|netgate|fortinet|sophos|watchguard|palo alto/i],
        ['network', /ubiquiti|mikrotik|tp-link|netgear|cisco|juniper|aruba|hewlett packard enterprise|zyxel|d-link|linksys|avm gmbh|draytek|cambium|ruckus|edgecore|tenda|mercusys|eero|plume/i]
    ];

    function guessType(names, vendor) {
        for (var i = 0; i < names.length; i++) {
            var t = String(names[i] || '').toLowerCase().replace(/[-_.]+/g, ' ').trim();
            if (!t || /^([0-9a-f]{2} ?){6}$/.test(t)) { continue; }
            for (var j = 0; j < NAME_RULES.length; j++) {
                if (NAME_RULES[j][1].test(t)) { return [NAME_RULES[j][0], 'name']; }
            }
        }
        for (var k = 0; vendor && k < VENDOR_RULES.length; k++) {
            if (VENDOR_RULES[k][1].test(vendor)) { return [VENDOR_RULES[k][0], 'manufacturer']; }
        }
        return ['unknown', ''];
    }

    // ------------------------------------------------------------------
    // data model
    // ------------------------------------------------------------------
    var PALETTE = ['#3b82c4', '#2e9e6b', '#c9822b', '#8e5bc4', '#c4473b', '#2a9fb0', '#b0a02a', '#c45b9a', '#6b7c8c'];

    function Model() {
        this.nets = [];
        this.hosts = {};         // mac -> host
        this.byIp = {};          // ip -> host
        this.ownIps = {};
        this.states = {};        // state id -> {bytes: [a, b], t}
        this.traffic = {};       // ip -> {up, down, conns, total}
        this.blocked = {};       // ip -> {count, last}
        this.dns = {};           // ip -> name
        this.instanton = null;   // {clients: {mac: client}, topology: nodes}
        this.custom = {};        // mac -> {name, kind, notes} given in the map
        this.kea = {res: {}, subnets: []};  // Kea DHCPv4 reservations by MAC, subnets
        this.fw = {aliases: {}, rules: {}, forwards: []};  // blocking aliases and rules, port forwards
        this.updated = {};
    }

    Model.prototype.netOf = function (ip) {
        for (var i = 0; i < this.nets.length; i++) {
            if (inCidr(ip, this.nets[i].cidr)) { return this.nets[i]; }
        }
        return null;
    };

    Model.prototype.loadInterfaces = function (rows) {
        var nets = [], own = {}, wanNets = [], wanIf = '';
        $.each(rows || [], function (_, r) {
            if (!r.identifier || !r.addr4 || r.identifier === 'lo0') { return; }
            $.each(r.ipv4 || [], function (_, a) { own[String(a.ipaddr || a.address || '').split('/')[0]] = 1; });
            own[String(r.addr4).split('/')[0]] = 1;
            var bits = +String(r.addr4).split('/')[1];
            // an IPv4 gateway marks the uplink (an IPv6 router advertisement on a LAN does not)
            var wan = (r.gateways || []).some(function (g) { return String(g).indexOf(':') < 0; }) || /^wan\b/i.test(r.description || '');
            if (wan) {
                $.each(r.ipv4 || [{ipaddr: r.addr4}], function (_, a) { wanNets.push(a.ipaddr || a.address); });
                if (!wanIf && (r.gateways || []).some(function (g) { return String(g).indexOf(':') < 0; })) { wanIf = r.identifier; }
                return;
            }
            if (bits >= 31) { return; }
            nets.push({id: r.identifier, name: r.description || r.identifier, device: r.device, cidr: r.addr4,
                vlan: r.vlan_tag || (/vlan0?\.?(\d+)/.exec(r.device || '') || [])[1] || ''});
        });
        nets.sort(function (a, b) { return ipNum(a.cidr.split('/')[0]) - ipNum(b.cidr.split('/')[0]); });
        $.each(nets, function (i, n) { n.color = PALETTE[i % PALETTE.length]; });
        this.nets = nets;
        this.wanNets = wanNets;
        this.wanIf = wanIf;
        this.ownIps = own;
    };

    Model.prototype.host = function (mac) {
        mac = normMac(mac);
        if (!mac || mac === 'ff:ff:ff:ff:ff:ff') { return null; }
        if (!this.hosts[mac]) {
            this.hosts[mac] = {mac: mac, ip: '', ips: {}, names: [], vendor: '', lastSeen: 0, firstSeen: 0, online: false,
                random: isRandomMac(mac)};
        }
        return this.hosts[mac];
    };

    Model.prototype.addIp = function (h, ip, seen) {
        if (!ip || ip.indexOf(':') >= 0 || this.ownIps[ip]) { return; }
        // devices on the uplink side (the provider router's network) are not ours to map
        for (var i = 0; i < (this.wanNets || []).length; i++) { if (inCidr(ip, this.wanNets[i])) { return; } }
        var prev = h.ips[ip] || 0;
        h.ips[ip] = Math.max(prev, seen || 1);
    };

    Model.prototype.loadHosts = function (discovery, leases, arp) {
        var self = this;
        var fresh = {};
        $.each(discovery || [], function (_, r) {
            var h = self.host(r.ether_address);
            if (!h) { return; }
            fresh[h.mac] = 1;
            var seen = Date.parse(r.last_seen) / 1000 || 0;
            self.addIp(h, r.ip_address, seen);
            h.vendor = h.vendor || r.organization_name || '';
            h.lastSeen = Math.max(h.lastSeen, seen);
            var first = Date.parse(r.first_seen) / 1000 || 0;
            h.firstSeen = h.firstSeen ? Math.min(h.firstSeen, first) : first;
        });
        $.each(leases || [], function (_, r) {
            var h = self.host(r.hwaddr);
            if (!h) { return; }
            fresh[h.mac] = 1;
            self.addIp(h, r.address, (+r.expire || 0) - (+r.valid_lifetime || 0));
            h.lease = {hostname: String(r.hostname || '').replace(/\.$/, ''), reserved: r.is_reserved === '1' || r.is_reserved === true,
                expire: +r.expire || 0, iface: r.if_descr || ''};
        });
        var now = Date.now() / 1000;
        $.each(self.hosts, function (_, h) { h.online = false; });
        $.each(arp || [], function (_, r) {
            if (r.expired || r.intf_description === 'WAN') { return; }
            var h = self.host(r.mac);
            if (!h) { return; }
            fresh[h.mac] = 1;
            self.addIp(h, r.ip, now);
            h.online = true;
            h.vendor = h.vendor || r.manufacturer || '';
            if (r.hostname) { h.arpName = r.hostname; }
            h.lastSeen = Math.max(h.lastSeen, now);
        });
        // drop the firewall's own interfaces and hosts that left every source
        $.each(Object.keys(self.hosts), function (_, mac) {
            var h = self.hosts[mac];
            if (!fresh[mac] || !Object.keys(h.ips).length) { delete self.hosts[mac]; }
        });
        this.index();
    };

    Model.prototype.index = function () {
        var self = this, owners = [];
        self.byIp = {};
        $.each(self.hosts, function (_, h) {
            var ips = Object.keys(h.ips).filter(function (ip) { return !self.ownIps[ip] && self.netOf(ip); });
            ips.sort(function (a, b) { return h.ips[b] - h.ips[a]; });
            h.ip = ips[0] || Object.keys(h.ips)[0] || '';
            h.net = self.netOf(h.ip);
            $.each(ips, function (_, ip) { owners.push([ip, h]); });
            if (h.lastSeen && Date.now() / 1000 - h.lastSeen < 600) { h.online = true; }
            var ic = self.instanton && self.instanton.clients[h.mac];
            h.ic = ic || null;
            var cu = self.custom[h.mac] || {}, res = self.kea.res[h.mac] || null;
            h.custom = cu;
            h.res = res;
            h.approved = !!cu.approved;
            h.group = cu.group || '';
            h.autoName = (res && (res.description || res.hostname)) ||
                (ic && (ic.description || ic.hostname || ic.port_label || ic.cloud_name)) || (h.lease && h.lease.hostname) || h.arpName || '';
            h.name = cu.name || h.autoName;
            var kind = cu.kind && TYPES[cu.kind] ? [cu.kind, 'your choice'] :
                (ic && ic.type && ic.type !== 'unknown' ? [ic.type, 'Instant On'] : guessType([h.name, h.autoName], h.vendor));
            h.type = TYPES[kind[0]] ? kind[0] : 'unknown';
            h.typeSource = kind[1];
            // how it is connected: known from Instant On, otherwise a guess
            if (ic && ic.connection) {
                h.link = ic.connection === 'wireless' ? 'wifi' : 'lan';
                h.linkKnown = true;
            } else {
                // the firewall cannot see how a device reaches the switch: no guess is shown
                h.link = '';
                h.linkKnown = false;
            }
        });
        // several MAC addresses can share an address (virtual machines, bridges): the IP belongs to the
        // online host with a name, then to the one seen last
        function score(h) { return (h.online ? 4 : 0) + (h.name ? 2 : 0) + (h.lastSeen || 0) / 1e10; }
        $.each(owners, function (_, o) {
            var cur = self.byIp[o[0]];
            if (!cur || score(o[1]) > score(cur)) { self.byIp[o[0]] = o[1]; }
        });
    };

    Model.prototype.loadNames = function (devices, reservations, subnets) {
        var custom = {}, res = {};
        $.each(devices || [], function (_, d) { custom[normMac(d.mac)] = d; });
        $.each(reservations || [], function (_, r) { if (r.hw_address) { res[normMac(r.hw_address)] = r; } });
        this.custom = custom;
        this.kea = {res: res, subnets: $.map(subnets || [], function (sn) { return {uuid: sn.uuid, cidr: sn.subnet, name: sn.description || ''}; })};
    };

    Model.prototype.keaSubnetOf = function (ip) {
        for (var i = 0; i < this.kea.subnets.length; i++) { if (inCidr(ip, this.kea.subnets[i].cidr)) { return this.kea.subnets[i]; } }
        return null;
    };

    // per-IP traffic from the state table; rates from the change since the previous poll
    Model.prototype.loadStates = function (rows) {
        var self = this, now = Date.now() / 1000;
        var seen = {}, traffic = {}, tuples = {}, total = {up: 0, down: 0};
        function add(ip, up, down, dUp, dDown) {
            var t = traffic[ip] || (traffic[ip] = {up: 0, down: 0, conns: 0, sent: 0, received: 0});
            t.conns += 1;
            t.sent += up;
            t.received += down;
            t.up += dUp;
            t.down += dDown;
        }
        $.each(rows || [], function (_, s) {
            var b = s.bytes || [0, 0];
            var prev = self.states[s.id];
            var dt = prev ? now - prev.t : 0;
            var d0 = prev && dt > 0 ? Math.max(0, b[0] - prev.bytes[0]) * 8 / dt : 0;
            var d1 = prev && dt > 0 ? Math.max(0, b[1] - prev.bytes[1]) * 8 / dt : 0;
            seen[s.id] = {bytes: b, t: now};
            // a connection between two networks has a state on each interface: count it once
            var tuple = [s.proto, s.src_addr, s.src_port, s.dst_addr, s.dst_port].join('|');
            if (tuples[tuple]) { return; }
            tuples[tuple] = 1;
            if (self.byIp[s.src_addr] || self.byIp[s.dst_addr]) {
                total.up += self.byIp[s.src_addr] ? d0 : d1;
                total.down += self.byIp[s.src_addr] ? d1 : d0;
            }
            // bytes[0] travels from the source of the state to its destination
            if (self.byIp[s.src_addr]) { add(s.src_addr, b[0], b[1], d0, d1); }
            if (self.byIp[s.dst_addr]) { add(s.dst_addr, b[1], b[0], d1, d0); }
        });
        self.states = seen;
        self.traffic = traffic;
        self.total = total;
        self.statesAt = now;
    };

    Model.prototype.loadLog = function (rows) {
        var self = this, blocked = {};
        $.each(rows || [], function (_, r) {
            if (r.action !== 'block') { return; }
            var ts = Date.parse(r.__timestamp__) / 1000 || 0;
            $.each([r.src, r.dst], function (_, ip) {
                if (self.byIp[ip]) {
                    var b = blocked[ip] || (blocked[ip] = {count: 0, last: 0});
                    b.count++;
                    b.last = Math.max(b.last, ts);
                }
            });
        });
        self.log = rows || [];
        self.blocked = blocked;
    };

    Model.prototype.loadDns = function (rows) {
        var names = {}, cname = {};
        $.each(rows || [], function (_, r) {
            var host = String(r.host || '').replace(/\.$/, '');
            if (r.rrtype === 'A' || r.rrtype === 'AAAA') {
                if (!names[r.value] || host.length < names[r.value].length) { names[r.value] = host; }
            } else if (r.rrtype === 'CNAME') {
                cname[String(r.value || '').replace(/\.$/, '')] = host;
            }
        });
        // prefer the name that was asked for over the CDN name it points to
        $.each(names, function (ip, host) {
            var seen = 0;
            while (cname[host] && seen++ < 5) { host = cname[host]; }
            names[ip] = host;
        });
        this.dns = names;
    };

    Model.prototype.hostStats = function (h) {
        var t = {up: 0, down: 0, conns: 0, sent: 0, received: 0}, b = {count: 0, last: 0}, self = this;
        $.each(h.ips, function (ip) {
            var x = self.traffic[ip];
            if (x) { t.up += x.up; t.down += x.down; t.conns += x.conns; t.sent += x.sent; t.received += x.received; }
            var y = self.blocked[ip];
            if (y) { b.count += y.count; b.last = Math.max(b.last, y.last); }
        });
        return {traffic: t, blocked: b};
    };

    // ------------------------------------------------------------------
    // the page
    // ------------------------------------------------------------------
    function start($root) {
        var model = new Model();
        var filters = {q: '', nets: {}, link: '', type: '', active: false, offline: false, view: 'networks', sort: 'traffic'};
        try { $.extend(filters, JSON.parse(window.localStorage.getItem('netmap.filters') || '{}'), {q: ''}); } catch (e) { /* ignore */ }
        var selected = null;
        var timers = {};
        // Network Map > Settings
        var opts = {refresh: EVERY.states, new_devices: true, firewall_actions: true, scans: true, hidden_networks: [], adguard: false};

        $root.html(
            '<div class="nm-toolbar">' +
            '  <div class="btn-group nm-view" role="group" style="display:none">' +
            '    <button type="button" class="btn btn-default btn-sm" data-view="networks">' + icon('th-large') + ' Networks</button>' +
            '    <button type="button" class="btn btn-default btn-sm" data-view="physical">' + icon('sitemap') + ' Physical</button>' +
            '  </div>' +
            '  <input type="search" class="form-control input-sm nm-q" placeholder="Find name, IP, MAC or maker">' +
            '  <div class="btn-group nm-link" role="group" style="display:none">' +
            '    <button type="button" class="btn btn-default btn-sm" data-link="">All</button>' +
            '    <button type="button" class="btn btn-default btn-sm" data-link="lan"><span class="nm-lan-tag">LAN</span> Cable</button>' +
            '    <button type="button" class="btn btn-default btn-sm" data-link="wifi">' + icon('wifi') + ' Wi-Fi</button>' +
            '    <button type="button" class="btn btn-default btn-sm" data-link="none" title="Connection not known">?</button>' +
            '  </div>' +
            '  <div class="btn-group nm-filters-dd">' +
            '    <button type="button" class="btn btn-default btn-sm dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">' +
            icon('filter') + ' Filters <span class="badge nm-filter-count"></span> <span class="caret"></span></button>' +
            '    <div class="dropdown-menu nm-filter-menu">' +
            '      <label>Kind</label><select class="form-control input-sm nm-type"><option value="">everything</option></select>' +
            '      <div class="nm-group-wrap" style="display:none"><label>Group</label><select class="form-control input-sm nm-group">' +
            '<option value="">all groups</option></select></div>' +
            '      <label class="nm-check"><input type="checkbox" class="nm-active"> only devices talking now</label>' +
            '      <label class="nm-check"><input type="checkbox" class="nm-offline"> show offline devices too</label>' +
            '      <label class="nm-check" title="Devices with open ports at their last scan"><input type="checkbox" class="nm-withports"> only devices with open ports</label>' +
            '      <button type="button" class="btn btn-default btn-xs" data-reset-filters>' + icon('times') + ' Clear filters</button>' +
            '    </div>' +
            '  </div>' +
            '  <label class="nm-check" title="Look up the names of remote addresses the DNS cache does not know (reverse DNS) in the device panel: ' +
            'history, connections and blocked packets"><input type="checkbox" class="nm-resolve"> resolve hostnames</label>' +
            '  <select class="form-control input-sm nm-sort"><option value="traffic">by traffic</option><option value="name">by name</option>' +
            '    <option value="ip">by address</option></select>' +
            '  <button type="button" class="btn btn-default btn-sm nm-new-btn" title="Devices not approved yet">' +
            icon('star') + ' New <span class="badge nm-new-count"></span></button>' +
            '  <button type="button" class="btn btn-default btn-sm nm-restrict-btn" title="Banned devices, devices without Internet, port forwards">' +
            icon('ban') + ' Restrictions <span class="badge nm-restrict-count"></span></button>' +
            '  <span class="nm-status text-muted"></span>' +
            '</div>' +
            '<div class="nm-restrict" style="display:none"></div>' +
            '<div class="nm-adopt"></div>' +
            '<div class="nm-group-bar"></div>' +
            '<div class="nm-chips"></div>' +
            '<div class="nm-stage"></div>' +
            '<div class="nm-drawer" aria-hidden="true"></div>');
        var $stage = $root.find('.nm-stage'), $drawer = $root.find('.nm-drawer');
        // keep the panel below the fixed OPNsense header
        var $bar = $('.navbar-fixed-top, header.page-head').first();
        if ($bar.length) { $drawer.css('top', $bar.outerHeight() + 'px'); }

        function save() {
            try { window.localStorage.setItem('netmap.filters', JSON.stringify(filters)); } catch (e) { /* ignore */ }
        }

        function syncToolbar() {
            $root.find('[data-view]').removeClass('active').filter('[data-view="' + filters.view + '"]').addClass('active');
            $root.find('[data-link]').removeClass('active').filter('[data-link="' + filters.link + '"]').addClass('active');
            $root.find('.nm-active').prop('checked', filters.active);
            $root.find('.nm-offline').prop('checked', filters.offline);
            $root.find('.nm-sort').val(filters.sort);
            // the physical view needs switch and access point data: without it there is only one view and no choice
            var physical = !!(model.instanton && model.instanton.topology);
            $root.find('.nm-view').toggle(physical);
            if (!physical && filters.view !== 'networks') { filters.view = 'networks'; }
        }

        $root.on('click', '[data-view]', function () { filters.view = $(this).data('view'); save(); syncToolbar(); draw(); });
        $root.on('click', '[data-link]', function () { filters.link = $(this).data('link'); save(); syncToolbar(); draw(); });
        $root.on('input', '.nm-q', function () { filters.q = $(this).val().toLowerCase(); draw(); });
        $root.on('change', '.nm-type', function () { filters.type = $(this).val(); draw(); });
        $root.on('change', '.nm-active', function () { filters.active = this.checked; save(); draw(); });
        $root.on('change', '.nm-offline', function () { filters.offline = this.checked; save(); draw(); });
        $root.on('change', '.nm-withports', function () { filters.ports = this.checked; draw(); });
        $root.on('click', '.nm-filter-menu', function (e) { e.stopPropagation(); });
        $root.on('change', '.nm-sort', function () { filters.sort = $(this).val(); save(); draw(); });
        $root.on('click', '.nm-chip', function () {
            var id = $(this).data('net');
            filters.nets[id] = !filters.nets[id];
            save();
            draw();
        });
        $root.on('click', '.nm-card[data-mac]', function () { openDrawer($(this).data('mac')); });
        $root.on('keypress', '.nm-card[data-mac]', function (e) { if (e.which === 13) { openDrawer($(this).data('mac')); } });

        // ---- filtering ------------------------------------------------
        function visible(h, st) {
            if (!filters.offline && !h.online) { return false; }
            if (h.net && filters.nets[h.net.id]) { return false; }
            if (filters.link && (filters.link === 'none' ? h.link : h.link !== filters.link)) { return false; }
            if (filters.type && h.type !== filters.type) { return false; }
            if (filters.group && h.group !== filters.group) { return false; }
            if (filters.active && !(st.traffic.up + st.traffic.down > 0)) { return false; }
            if (onlyNew && h.approved) { return false; }
            if (filters.ports && !(model.scans && model.scans[h.mac] && model.scans[h.mac].open.length)) { return false; }
            if (filters.q) {
                var hay = [h.name, h.ip, h.mac, h.vendor, TYPES[h.type][0], h.ic && h.ic.ssid, h.ic && h.ic.ap].join(' ').toLowerCase();
                if (hay.indexOf(filters.q) < 0) { return false; }
            }
            return true;
        }

        function sorter(a, b) {
            if (filters.sort === 'name') { return (a.h.name || a.h.ip).localeCompare(b.h.name || b.h.ip, undefined, {numeric: true}); }
            if (filters.sort === 'ip') { return (ipNum(a.h.ip) || 0) - (ipNum(b.h.ip) || 0); }
            var ta = a.st.traffic.up + a.st.traffic.down, tb = b.st.traffic.up + b.st.traffic.down;
            return tb - ta || (b.st.traffic.sent + b.st.traffic.received) - (a.st.traffic.sent + a.st.traffic.received);
        }

        // ---- cards ----------------------------------------------------
        function linkBadge(h) {
            if (h.link === 'wifi') {
                var ic = h.ic || {};
                var bars = ic.snr === null || ic.snr === undefined ? null : (ic.snr >= 35 ? 4 : ic.snr >= 25 ? 3 : ic.snr >= 15 ? 2 : 1);
                var title = h.linkKnown ? 'Wi-Fi' + (ic.ssid ? ' "' + ic.ssid + '"' : '') + (ic.band ? ' ' + ic.band : '') +
                    (ic.ap ? ' via ' + ic.ap : '') + (ic.snr !== undefined && ic.snr !== null ? ', signal ' + ic.snr + ' dB' : '')
                    : 'Probably Wi-Fi (private address or mobile device)';
                return '<span class="nm-link nm-wifi' + (h.linkKnown ? '' : ' nm-guess') + '" title="' + esc(title) + '">' +
                    (bars ? '<span class="nm-bars nm-bars-' + bars + '"><i></i><i></i><i></i><i></i></span>' : icon('wifi')) +
                    (ic.band ? '<small>' + esc(String(ic.band).replace('ghz', '')) + '</small>' : '') + '</span>';
            }
            if (h.link === 'lan') {
                var p = h.ic && h.ic.port ? (h.ic.switch_name ? h.ic.switch_name + ' ' : '') + h.ic.port : '';
                return '<span class="nm-link nm-lan' + (h.linkKnown ? '' : ' nm-guess') + '" title="' +
                    esc(h.linkKnown ? 'Cable' + (p ? ', switch port ' + p : '') : 'Probably cable (kind of device)') + '">' +
                    '<span class="nm-lan-tag">LAN</span>' + (p ? '<small>' + esc(h.ic.port) + '</small>' : '') + '</span>';
            }
            return '';
        }

        function card(h, st) {
            var t = st.traffic, live = t.up + t.down;
            var level = live > 5e6 ? 4 : live > 5e5 ? 3 : live > 2e4 ? 2 : live > 0 ? 1 : 0;
            return '<div class="nm-card nm-act-' + level + (h.online ? '' : ' nm-off') + (selected === h.mac ? ' nm-sel' : '') +
                '" data-mac="' + esc(h.mac) + '" tabindex="0" role="button" style="--net:' + (h.net ? h.net.color : '#999') + '">' +
                '<span class="nm-ico" title="' + esc(TYPES[h.type][0] + (h.typeSource ? ' (from ' + h.typeSource + ')' : '')) + '">' +
                icon(TYPES[h.type][1]) + '</span>' +
                '<span class="nm-body"><span class="nm-name">' + (h.approved || !anyApproved() ? '' : '<span class="nm-new-tag">new</span>') +
                esc(h.name || h.ip || h.mac) + '</span>' +
                '<span class="nm-sub">' + esc(h.name ? h.ip : (h.random ? 'private MAC' : h.vendor || h.mac)) + '</span>' +
                '<span class="nm-rate">' + (live > 0 ? icon('arrow-down') + esc(rate(t.down)) + ' ' + icon('arrow-up') + esc(rate(t.up))
                    : (t.conns ? esc(t.conns) + ' conn.' : (h.online ? 'idle' : 'offline ' + esc(ago(h.lastSeen))))) + '</span></span>' +
                '<span class="nm-side">' + linkBadge(h) +
                (model.scans && model.scans[h.mac] && model.scans[h.mac].open.length ? '<span class="nm-ports-tag" title="' +
                    esc(model.scans[h.mac].open.length + ' open ports at the last scan (' + ago(model.scans[h.mac].finished) + '): ' +
                        $.map(model.scans[h.mac].open, function (p) { return p.port + '/' + p.proto + (p.service ? ' ' + p.service : ''); }).join(', ')) +
                    '">' + icon('door-open') + esc(model.scans[h.mac].open.length) + '</span>' : '') +
                (st.blocked.count ? '<span class="nm-blk" title="' + esc(st.blocked.count + ' packets blocked by the firewall, last ' +
                    ago(st.blocked.last)) + '">' + icon('ban') + esc(st.blocked.count) + '</span>' : '') + '</span>' +
                '<span class="nm-meter"><i style="width:' + Math.min(100, level * 25) + '%"></i></span></div>';
        }

        function chips(groups) {
            var html = $.map(model.nets, function (n) {
                var g = groups[n.id] || {count: 0, up: 0, down: 0};
                return '<button type="button" class="nm-chip' + (filters.nets[n.id] ? ' nm-chip-off' : '') + '" data-net="' + esc(n.id) +
                    '" style="--net:' + n.color + '" title="' + esc(n.cidr + (n.vlan ? ', VLAN ' + n.vlan : '') + ' - click to hide or show') + '">' +
                    '<b>' + esc(n.name) + '</b> <span>' + esc(g.count) + '</span>' +
                    (g.up + g.down > 0 ? ' <small>' + esc(rate(g.up + g.down)) + '</small>' : '') + '</button>';
            }).join('');
            $root.find('.nm-chips').html(html);
        }

        function groupNames() {
            var seen = {};
            $.each(model.custom, function (_, c) { if (c.group) { seen[c.group] = 1; } });
            return Object.keys(seen).sort(function (a, b) { return a.localeCompare(b); });
        }

        function fillGroups() {
            var names = groupNames();
            if (filters.group && names.indexOf(filters.group) < 0) { filters.group = ''; }
            var html = '<option value="">all groups</option>' + $.map(names, function (g) {
                return '<option value="' + esc(g) + '">' + esc(g) + '</option>';
            }).join('');
            var $s = $root.find('.nm-group');
            if ($s.data('html') !== html) { $s.data('html', html).html(html).val(filters.group); }
            $root.find('.nm-group-wrap').toggle(names.length > 0);
            // actions on every device of the selected group
            var $bar = $root.find('.nm-group-bar');
            if (!filters.group) { $bar.empty(); return; }
            var members = $.grep($.map(model.hosts, function (h) { return h; }), function (h) { return h.group === filters.group; });
            var blocked = $.grep(members, function (h) { return isMember('nowan', h.mac); }).length;
            $bar.html('<div class="alert alert-info nm-group-box">' + icon('object-group') + ' Group <b>' + esc(filters.group) + '</b>: ' +
                esc(members.length) + ' devices, ' + esc(blocked) + ' without Internet. ' +
                '<button type="button" class="btn btn-warning btn-xs" data-group-net="1">' + icon('ban') + ' Block Internet for all</button> ' +
                '<button type="button" class="btn btn-success btn-xs" data-group-net="0">' + icon('unlock') + ' Allow Internet for all</button></div>');
        }

        $root.on('change', '.nm-group', function () { filters.group = $(this).val(); save(); draw(); });
        $root.on('click', '[data-group-net]', function () {
            var on = $(this).data('group-net') === 1, group = filters.group;
            var macs = $.map(model.hosts, function (h) { return h.group === group ? h.mac : null; });
            if (!macs.length) { return; }
            confirmDialog(on ? 'Block Internet for a group' : 'Allow Internet for a group',
                '<p>' + (on ? 'Block' : 'Allow') + ' Internet access for the <b>' + esc(macs.length) + '</b> devices of the group <b>' +
                esc(group) + '</b>?</p><ul class="nm-modal-points"><li>' + (on ? 'They can still reach the local networks and the firewall.'
                    : 'Their Internet access follows your other rules again.') + '</li><li>Devices added to the group later are not ' +
                'included automatically.</li></ul>', on ? 'Block Internet' : 'Allow Internet', on)
                .done(function () {
                    setMembers('nowan', macs, on).always(function () { loadFirewall().always(draw); });
                });
        });

        function fillTypes() {
            var seen = {};
            $.each(model.hosts, function (_, h) { seen[h.type] = 1; });
            var html = '<option value="">everything</option>' + $.map(Object.keys(seen).sort(function (a, b) {
                return TYPES[a][0].localeCompare(TYPES[b][0]);
            }), function (t) { return '<option value="' + t + '">' + esc(TYPES[t][0]) + '</option>'; }).join('');
            var $s = $root.find('.nm-type');
            if ($s.data('html') !== html) { $s.data('html', html).html(html).val(filters.type); }
        }

        // ---- networks view ---------------------------------------------
        function drawNetworks(items) {
            var byNet = {};
            $.each(items, function (_, it) { var id = it.h.net ? it.h.net.id : '_'; (byNet[id] = byNet[id] || []).push(it); });
            var total = model.total || {up: 0, down: 0};
            var html = '<div class="nm-root"><div class="nm-fw">' + icon('shield') + '<div><b>Firewall</b><small>' +
                esc(items.length) + ' devices &middot; ' + icon('arrow-down') + esc(rate(total.down)) + ' ' + icon('arrow-up') +
                esc(rate(total.up)) + '</small></div></div></div><div class="nm-nets">';
            $.each(model.nets.concat([{id: '_', name: 'Other addresses', cidr: '', color: '#999'}]), function (_, n) {
                var list = byNet[n.id];
                if (!list || !list.length || filters.nets[n.id]) { return; }
                list.sort(sorter);
                var up = 0, down = 0;
                $.each(list, function (_, it) { up += it.st.traffic.up; down += it.st.traffic.down; });
                html += '<section class="nm-net" style="--net:' + n.color + '"><header><span class="nm-dot"></span><b>' + esc(n.name) +
                    '</b><span class="text-muted">' + esc(n.cidr) + (n.vlan ? ' &middot; VLAN ' + esc(n.vlan) : '') + '</span>' +
                    '<span class="nm-net-stat">' + esc(list.length) + ' ' + icon('desktop') + ' &nbsp;' + icon('arrow-down') + esc(rate(down)) +
                    ' ' + icon('arrow-up') + esc(rate(up)) + '</span></header><div class="nm-grid">' +
                    $.map(list, function (it) { return card(it.h, it.st); }).join('') + '</div></section>';
            });
            $stage.html(html + '</div>');
        }

        // ---- physical view (Instant On topology) ------------------------
        // Laid out like the networks view: one panel per switch on the trunk, inside it one block per access point
        // (meshed access points inside the one they hang from) and one for the devices on a cable.
        function drawPhysical(items) {
            var nodes = model.instanton.topology, kids = {}, root = null, shown = {}, placed = {};
            $.each(items, function (_, it) { shown[it.h.mac] = it; });
            $.each(nodes, function (_, n) {
                if (!n.parent) { root = n; } else { (kids[n.parent] = kids[n.parent] || []).push(n); }
            });
            if (!root) { drawNetworks(items); return; }

            function linkText(l) {
                l = l || {};
                return [l.text, l.speed, l.poe_w ? l.poe_w + ' W' : '', l.snr !== undefined && l.snr !== null ? l.snr + ' dB' : '']
                    .filter(Boolean).join(' · ');
            }

            function leavesOf(n) {
                var out = [];
                $.each(kids[n.id] || [], function (_, c) {
                    if (c.client && shown[c.mac]) { out.push(shown[c.mac]); placed[c.mac] = 1; }
                });
                return out.sort(sorter);
            }

            function grid(list, empty) {
                return list.length ? '<div class="nm-grid">' + $.map(list, function (it) { return card(it.h, it.st); }).join('') + '</div>'
                    : '<p class="small text-muted">' + esc(empty) + '</p>';
            }

            function apBlock(ap, depth) {
                var clients = leavesOf(ap);
                var mesh = $.grep(kids[ap.id] || [], function (c) { return !c.client && c.type === 'ap'; });
                var l = ap.link || {};
                return '<div class="nm-box nm-box-ap' + (l.kind === 'mesh' ? ' nm-box-mesh' : '') + (ap.online === false ? ' nm-off' : '') + '">' +
                    '<header>' + icon('wifi') + ' <b>' + esc(ap.label) + '</b><span class="text-muted">' + esc(ap.sub || '') + '</span>' +
                    '<span class="nm-box-link">' + (l.kind === 'mesh' ? icon('random') + ' ' : '') + esc(linkText(l)) + '</span>' +
                    '<span class="nm-net-stat">' + esc(clients.length) + ' ' + icon('mobile') + '</span></header>' +
                    grid(clients, 'No client on this access point.') +
                    $.map(mesh, function (m) { return apBlock(m, depth + 1); }).join('') + '</div>';
            }

            function switchPanel(sw) {
                var wired = leavesOf(sw);
                var aps = $.grep(kids[sw.id] || [], function (c) { return !c.client && c.type === 'ap'; });
                var subs = $.grep(kids[sw.id] || [], function (c) { return !c.client && c.type === 'switch'; });
                var l = sw.link || {};
                return '<section class="nm-net nm-phys" style="--net:#2e9e6b"><header>' + icon('sitemap') + ' <b>' + esc(sw.label) + '</b>' +
                    '<span class="text-muted">' + esc(sw.sub || '') + '</span><span class="nm-box-link" title="Link towards the firewall">' +
                    esc(linkText(l)) + '</span><span class="nm-net-stat">' + esc(aps.length) + ' ' + icon('wifi') + ' &nbsp;' + esc(wired.length) + ' ' +
                    icon('plug') + '</span></header>' +
                    $.map(aps, function (a) { return apBlock(a, 0); }).join('') +
                    '<div class="nm-box nm-box-wired"><header>' + icon('plug') + ' <b>On a cable</b><span class="nm-net-stat">' + esc(wired.length) +
                    '</span></header>' + grid(wired, 'No device on a cable.') + '</div>' +
                    $.map(subs, function (x) {
                        return x.unmanaged ? '<div class="nm-box nm-box-unmanaged"><header>' + icon('sitemap') + ' <b>' + esc(x.label) +
                            '</b><span class="text-muted">not monitored</span><span class="nm-box-link">' + esc(linkText(x.link)) + '</span></header>' +
                            grid(leavesOf(x), 'No device seen behind it.') + '</div>' : switchPanel(x);
                    }).join('') + '</section>';
            }

            var switches = $.grep(kids[root.id] || [], function (c) { return !c.client && c.type === 'switch'; });
            var topAps = $.grep(kids[root.id] || [], function (c) { return !c.client && c.type === 'ap'; });
            var total = model.total || {up: 0, down: 0};
            var html = '<div class="nm-root"><div class="nm-fw">' + icon('shield') + '<div><b>Firewall</b><small>' + esc(items.length) +
                ' devices &middot; ' + icon('arrow-down') + esc(rate(total.down)) + ' ' + icon('arrow-up') + esc(rate(total.up)) +
                '</small></div></div></div><div class="nm-nets">' + $.map(switches, switchPanel).join('') +
                $.map(topAps, function (a) { return '<section class="nm-net nm-phys" style="--net:#3b82c4">' + apBlock(a, 0) + '</section>'; }).join('');
            var rest = items.filter(function (it) { return !placed[it.h.mac]; });
            rest.sort(sorter);
            if (rest.length) {
                html += '<section class="nm-net" style="--net:#999"><header><b>Not on a monitored switch</b><span class="text-muted">other networks, ' +
                    'VPN, or seen only by the firewall</span><span class="nm-net-stat">' + esc(rest.length) + '</span></header>' + grid(rest, '') + '</section>';
            }
            $stage.html(html + '</div>');
        }

        var loaded = false;

        function draw() {
            if (!loaded) { return; }
            // the New filter switches itself off once every device is approved
            if (onlyNew && !newDevices().length) { onlyNew = false; }
            var items = [], groups = {};
            $.each(model.hosts, function (_, h) {
                var st = model.hostStats(h);
                if (h.net) {
                    var g = groups[h.net.id] || (groups[h.net.id] = {count: 0, up: 0, down: 0});
                    if (h.online) { g.count++; }
                    g.up += st.traffic.up;
                    g.down += st.traffic.down;
                }
                if (visible(h, st)) { items.push({h: h, st: st}); }
            });
            chips(groups);
            fillTypes();
            var nBlocked = 0;
            $.each(FW, function (_, def) { var a = model.fw.aliases[def.alias]; nBlocked += a ? a.content.length : 0; });
            $root.find('.nm-restrict-count').text(nBlocked || '');
            adoptBanner();
            fillGroups();
            var active = (filters.type ? 1 : 0) + (filters.group ? 1 : 0) + (filters.active ? 1 : 0) + (filters.offline ? 1 : 0) + (filters.ports ? 1 : 0);
            $root.find('.nm-filter-count').text(active || '');
            $root.find('.nm-filters-dd > .btn').toggleClass('active', active > 0);
            // cable / Wi-Fi filters only make sense when switch and access point data tell it
            var exact = !!(model.instanton && model.instanton.clients);
            $root.find('.nm-toolbar .nm-link').toggle(exact);
            if (!exact && filters.link) { filters.link = ''; }
            if (!items.length && Object.keys(model.hosts).length) {
                $stage.html('<div class="nm-empty">' + icon('filter') + '<p>No device matches the current filters.</p>' +
                    '<button type="button" class="btn btn-default btn-sm" data-reset-filters>Show every device</button></div>');
            } else if (filters.view === 'physical' && model.instanton && model.instanton.topology) {
                drawPhysical(items);
            } else {
                drawNetworks(items);
            }
            if (selected) { renderDrawer(); }
        }

        // ---- device drawer ---------------------------------------------
        // the panel is split in tabs; the last one used is remembered
        var TABS = [['device', 'Device', 'info-circle'], ['traffic', 'Traffic', 'exchange'], ['security', 'Security', 'shield'],
            ['dns', 'DNS', 'globe']];
        var drawerTab = 'device';
        try { drawerTab = window.localStorage.getItem('netmap.tab') || 'device'; } catch (e) { /* ignore */ }

        var drawerData = {rows: [], prev: {}, history: [], log: [], scan: null};

        function openDrawer(mac) {
            selected = mac;
            editing = null;
            drawerData = {rows: [], prev: {}, history: [], log: [], scan: null, hist: null, dns: null};
            loadHistory();
            loadAdguard();
            $drawer.html('<div class="nm-dtop"></div><div class="nm-dedit"></div><div class="nm-dlive"></div>');
            $drawer.addClass('nm-open').attr('aria-hidden', 'false');
            renderEdit();
            loadScan();
            $stage.find('.nm-sel').removeClass('nm-sel');
            $stage.find('[data-mac="' + mac + '"]').addClass('nm-sel');
            renderDrawer();
            pollDevice();
        }

        function closeDrawer() {
            selected = null;
            clearTimeout(timers.live);
            clearTimeout(timers.scan);
            $drawer.removeClass('nm-open').attr('aria-hidden', 'true').empty();
            $stage.find('.nm-sel').removeClass('nm-sel');
        }

        $drawer.on('click', '.nm-close', closeDrawer);
        $drawer.on('click', '[data-dtab]', function (e) {
            e.preventDefault();
            drawerTab = $(this).data('dtab');
            try { window.localStorage.setItem('netmap.tab', drawerTab); } catch (ex) { /* ignore */ }
            $drawer.attr('data-tab', drawerTab).find('.nm-dtabs li').removeClass('active');
            $(this).parent().addClass('active');
            $drawer.scrollTop(0);
        });
        $(document).on('keydown', function (e) { if (e.key === 'Escape' && selected) { closeDrawer(); } });
        // a click anywhere outside the panel closes it (a click on another device opens that one instead)
        $(document).on('mousedown', function (e) {
            if (selected && !$('.nm-modal').length && !$(e.target).closest('.nm-drawer, .nm-card, .modal, .modal-backdrop, .bootstrap-dialog').length) { closeDrawer(); }
        });

        // ---- port scan (nmap on the firewall) ----------------------------
        function loadScan() {
            clearTimeout(timers.scan);
            var h = model.hosts[selected];
            if (!h || !h.ip) { return; }
            var mac = selected;
            get('netmap/scan/status/' + h.mac.replace(/:/g, '-')).done(function (d) {
                if (selected !== mac) { return; }
                drawerData.scan = d;
                if (d && d.status === 'done') {
                    // keep the badge on the map card in step with the scan just read
                    model.scans = model.scans || {};
                    model.scans[mac] = {mac: mac, finished: d.finished, open: $.map(d.ports || [], function (p) {
                        return {port: p.port, proto: p.proto, service: p.service};
                    })};
                }
                renderDrawer();
                if (d && d.status === 'running') { timers.scan = setTimeout(loadScan, 3000); }
            }).fail(function (xhr) {
                if (selected === mac) { drawerData.scan = {status: 'unavailable', code: xhr.status}; renderDrawer(); }
            });
        }

        function startScan(profile) {
            var h = model.hosts[selected];
            if (!h || !h.ip) { return; }
            drawerData.scan = {status: 'running', profile: profile, started: Date.now() / 1000};
            renderDrawer();
            search('netmap/scan/start/' + h.mac.replace(/:/g, '-') + '/' + encodeURIComponent(h.ip) + '/' + profile, {}).done(function (d) {
                drawerData.scan = d;
                renderDrawer();
                if (d && d.status === 'running') { timers.scan = setTimeout(loadScan, 3000); }
            }).fail(function (xhr) {
                drawerData.scan = {status: 'error', message: xhr.status === 403 ? 'your account may not start scans ' +
                    '(privilege "Reporting: Network Map: scan devices")' : 'HTTP ' + xhr.status};
                renderDrawer();
            });
        }

        $drawer.on('click', '[data-scan]', function () { startScan($(this).data('scan')); });

        function portSet(scan) {
            var out = {};
            $.each((scan && scan.ports) || [], function (_, p) { out[p.port + '/' + p.proto] = p.service || ''; });
            return out;
        }

        // earlier scans of the device, each with what changed compared with the scan before it
        function scanHistoryHtml(sc) {
            var list = [sc].concat(sc.history || []);
            if (list.length < 2) { return ''; }
            var rows = [];
            for (var i = 1; i < list.length; i++) {
                var newer = portSet(list[i - 1]), older = portSet(list[i]);
                var opened = $.grep(Object.keys(newer), function (k) { return older[k] === undefined; });
                var closed = $.grep(Object.keys(older), function (k) { return newer[k] === undefined; });
                rows.push('<li><div class="nm-l1"><span class="nm-r-name small">' + esc(new Date((list[i].finished || 0) * 1000).toLocaleString()) +
                    '</span><span class="nm-r-port">' + esc(list[i].profile || '') + (list[i].ip ? ' · ' + esc(list[i].ip) : '') + '</span>' +
                    '<span class="nm-r-rate small">' + esc(Object.keys(older).length) + ' open</span></div>' +
                    '<div class="nm-l2">' + (opened.length || closed.length ? $.map(opened, function (k) {
                        return '<span class="text-warning">' + icon('plus') + ' ' + esc(k) + ' opened since</span>';
                    }).join('') + $.map(closed, function (k) {
                        return '<span class="text-success">' + icon('minus') + ' ' + esc(k) + ' closed since</span>';
                    }).join('') : '<span>no change in the next scan</span>') + '</div></li>');
            }
            return '<details class="nm-scan-hist"><summary class="small">' + esc(list.length - 1) + ' earlier scan' +
                (list.length > 2 ? 's' : '') + '</summary><ul class="nm-list">' + rows.join('') + '</ul></details>';
        }

        function scanHtml(h) {
            var sc = drawerData.scan;
            if (!opts.scans && (!sc || sc.status === 'none')) { return '<p class="small text-muted">Port scans are turned off in Settings.</p>'; }
            var buttons = !opts.scans ? '' : '<div class="nm-scan-tools"><button type="button" class="btn btn-default btn-xs" data-scan="quick" ' +
                'title="The 200 most common ports with service names, about a minute">' + icon('search') + ' Quick scan</button> ' +
                '<button type="button" class="btn btn-default btn-xs" data-scan="full" title="Every TCP port, service versions and ' +
                'operating system, several minutes">' + icon('crosshairs') + ' Full scan</button></div>';
            var note = '<p class="small text-muted">Scans are performed by nmap on the firewall and are limited to hosts on ' +
                'directly connected internal networks. A full scan sends a large number of probes and may affect devices with ' +
                'limited network stacks; for such devices a quick scan is recommended.</p>';
            if (!sc) { return '<p class="text-muted small">' + icon('spinner fa-pulse') + ' reading...</p>'; }
            if (sc.status === 'unavailable') {
                return '<p class="text-muted small">Port scans are not available' + (sc.code === 403 ? ' for your account.' : ' (the plugin backend does not answer).') + '</p>';
            }
            if (sc.status === 'running') {
                return '<p>' + icon('spinner fa-pulse') + ' ' + esc(sc.profile === 'full' ? 'Full' : 'Quick') + ' scan running for ' +
                    esc(Math.round(Date.now() / 1000 - (sc.started || Date.now() / 1000))) + ' s...</p>' + note;
            }
            var html = buttons;
            if (sc.status === 'error') { html += '<p class="text-danger small">' + icon('exclamation-triangle') + ' ' + esc(sc.message || 'scan failed') + '</p>'; }
            if (sc.status === 'done') {
                var earlier = (sc.history || [])[0];
                var prev = {};
                $.each((earlier && earlier.ports) || [], function (_, p) { prev[p.proto + p.port] = 1; });
                var hasPrev = !!(earlier && earlier.ports);
                if (sc.seen_mac && sc.seen_mac !== h.mac) {
                    html += '<p class="small text-warning">' + icon('exclamation-triangle') + ' During this scan ' + esc(sc.ip) +
                        ' answered with another MAC address (' + esc(sc.seen_mac) + '): the results may belong to another device.</p>';
                }
                html += '<p class="small text-muted">' + esc(sc.profile === 'full' ? 'Full' : 'Quick') + ' scan ' + esc(ago(sc.finished)) +
                    (sc.elapsed ? ', ' + esc(Math.round(sc.elapsed)) + ' s' : '') + (sc.up === false ? ' &middot; the device did not answer' : '') +
                    (sc.closed ? ' &middot; ' + esc(sc.closed) + ' ports closed or filtered' : '') + '</p>';
                if (sc.os && sc.os.length) {
                    html += '<p class="small">' + icon('desktop') + ' System: <b>' + esc(sc.os[0].name) + '</b> <span class="text-muted">(' +
                        esc(sc.os[0].accuracy) + '% sure)</span></p>';
                }
                html += sc.ports && sc.ports.length ? '<ul class="nm-list nm-ports">' + $.map(sc.ports, function (p) {
                    var web = /^https?/.test(p.service) || p.tunnel === 'ssl' && /http/.test(p.service);
                    var scheme = p.tunnel === 'ssl' || p.service === 'https' ? 'https' : 'http';
                    return '<li><div class="nm-l1"><span class="nm-r-name">' + esc(p.port) + '/' + esc(p.proto) + '</span>' +
                        '<span class="nm-r-port">' + esc(p.service || '?') + '</span>' +
                        (hasPrev && !prev[p.proto + p.port] ? '<span class="label label-warning">new</span>' : '') +
                        '<span class="nm-r-rate">' + (web ? '<a href="' + esc(scheme + '://' + h.ip + ':' + p.port + '/') + '" target="_blank" ' +
                        'rel="noopener">' + icon('external-link') + ' open</a>' : '') + '</span></div>' +
                        ((p.product || p.version || p.extra) ? '<div class="nm-l2"><span>' + esc([p.product, p.version, p.extra ? '(' + p.extra + ')' : '']
                            .filter(Boolean).join(' ')) + '</span></div>' : '') + '</li>';
                }).join('') + '</ul>' : '<p class="small text-success">' + icon('check') + ' No open ports found.</p>';
                html += scanHistoryHtml(sc);
            }
            return html + note;
        }

        function pollDevice() {
            clearTimeout(timers.live);
            var h = model.hosts[selected];
            if (!h || !h.ip) { return; }
            var ip = h.ip;
            search('diagnostics/firewall/query_states', {current: 1, rowCount: 500, searchPhrase: ip}).done(function (d) {
                if (!selected || model.hosts[selected] !== h) { return; }
                var now = Date.now() / 1000, rows = [], up = 0, down = 0;
                var tuples = {};
                $.each(d.rows || [], function (_, s) {
                    var local = s.src_addr === ip ? 0 : (s.dst_addr === ip ? 1 : -1);
                    var tuple = [s.proto, s.src_addr, s.src_port, s.dst_addr, s.dst_port].join('|');
                    if (local < 0 || tuples[tuple]) { return; }
                    tuples[tuple] = 1;
                    var b = s.bytes || [0, 0], prev = drawerData.prev[s.id];
                    var dt = prev ? now - prev.t : 0;
                    var r0 = prev && dt > 0 ? Math.max(0, b[0] - prev.b[0]) * 8 / dt : 0;
                    var r1 = prev && dt > 0 ? Math.max(0, b[1] - prev.b[1]) * 8 / dt : 0;
                    drawerData.prev[s.id] = {b: b, t: now};
                    var row = {
                        id: s.id, proto: s.proto, outbound: local === 0,
                        remote: local === 0 ? s.dst_addr : s.src_addr, rport: local === 0 ? s.dst_port : s.src_port,
                        lport: local === 0 ? s.src_port : s.dst_port,
                        up: local === 0 ? r0 : r1, down: local === 0 ? r1 : r0,
                        sent: local === 0 ? b[0] : b[1], received: local === 0 ? b[1] : b[0],
                        rule: s.descr || '', state: s.state, age: s.age, nat: s.nat_addr
                    };
                    up += row.up;
                    down += row.down;
                    rows.push(row);
                });
                rows.sort(function (a, b) { return (b.up + b.down) - (a.up + a.down) || (b.sent + b.received) - (a.sent + a.received); });
                drawerData.rows = rows;
                drawerData.history.push({up: up, down: down});
                if (drawerData.history.length > HISTORY) { drawerData.history.shift(); }
                drawerData.log = $.grep(model.log || [], function (r) {
                    return r.action === 'block' && h.ips && (h.ips[r.src] || h.ips[r.dst]);
                });
                renderDrawer();
            }).always(function () {
                if (selected && !document.hidden) { timers.live = setTimeout(pollDevice, EVERY.live * 1000); }
            });
        }

        function remoteName(ip) {
            var h = model.byIp[ip];
            if (h) { return h.name || h.ip; }
            if (model.ownIps[ip]) { return 'this firewall'; }
            if (model.dns[ip]) { return model.dns[ip]; }
            if (resolveNames && rdns[ip] === undefined) { wantNames[ip] = 1; }
            return rdns[ip] || '';
        }

        // reverse DNS for addresses the resolver cache does not name (same lookup as the firewall live log)
        var resolveNames = false, rdns = {}, wantNames = {}, rdnsBusy = false;
        try { resolveNames = window.localStorage.getItem('netmap.resolve') === '1'; } catch (e) { /* ignore */ }

        function lookupNames() {
            var ips = Object.keys(wantNames).filter(function (ip) { return rdns[ip] === undefined; }).slice(0, 40);
            wantNames = {};
            if (!resolveNames || rdnsBusy || !ips.length) { return; }
            rdnsBusy = true;
            $.each(ips, function (_, ip) { rdns[ip] = ''; });  // asked once, even when there is no answer
            $.ajax({url: API + 'diagnostics/dns/reverse_lookup', data: {address: ips}, traditional: false, dataType: 'json',
                cache: false, global: false}).done(function (d) {
                $.each(d || {}, function (ip, name) { if (name && name !== ip) { rdns[ip] = String(name).replace(/\.$/, ''); } });
            }).always(function () {
                rdnsBusy = false;
                if (selected) { renderDrawer(); }
            });
        }

        $root.find('.nm-resolve').prop('checked', resolveNames);
        $root.on('change', '.nm-resolve', function () {
            resolveNames = this.checked;
            try { window.localStorage.setItem('netmap.resolve', resolveNames ? '1' : '0'); } catch (e) { /* ignore */ }
            renderDrawer();
        });

        function chart() {
            var hist = drawerData.history, w = 320, hgt = 70;
            if (hist.length < 2) { return '<div class="nm-chart nm-chart-empty text-muted small">Measuring... the rate appears after a few seconds.</div>'; }
            var max = Math.max.apply(null, $.map(hist, function (x) { return Math.max(x.up, x.down); }).concat([1000]));
            function line(key) {
                return $.map(hist, function (x, i) {
                    return (i * w / (HISTORY - 1)).toFixed(1) + ',' + (hgt - 2 - (x[key] / max) * (hgt - 6)).toFixed(1);
                }).join(' ');
            }
            var last = hist[hist.length - 1];
            return '<div class="nm-chart"><svg viewBox="0 0 ' + w + ' ' + hgt + '" preserveAspectRatio="none">' +
                '<polyline class="nm-down" points="' + line('down') + '"/><polyline class="nm-up" points="' + line('up') + '"/></svg>' +
                '<div class="nm-legend"><span class="nm-down">' + icon('arrow-down') + ' ' + esc(rate(last.down)) + '</span>' +
                '<span class="nm-up">' + icon('arrow-up') + ' ' + esc(rate(last.up)) + '</span><span class="text-muted">peak ' +
                esc(rate(max)) + '</span></div></div>';
        }

        function renderDrawer() {
            var h = model.hosts[selected];
            if (!h) { closeDrawer(); return; }
            var st = model.hostStats(h), ic = h.ic || {};
            var facts = [
                ['Address', esc(Object.keys(h.ips).join(', '))],
                ['MAC', '<code>' + esc(h.mac) + '</code>' + (h.random ? ' <span class="label label-default">private</span>' : '')],
                ['Maker', esc(h.vendor)],
                ['Network', h.net ? '<span class="nm-dot" style="--net:' + h.net.color + '"></span> ' + esc(h.net.name) + ' <span class="text-muted">' +
                    esc(h.net.cidr) + '</span>' : ''],
                ['Connection', h.link ? linkBadge(h) + ' ' + esc(h.link === 'wifi' ? 'Wi-Fi' : 'cable') + 
                    (ic.ap ? ' via <b>' + esc(ic.ap) + '</b>' : '') + (ic.ssid ? ' "' + esc(ic.ssid) + '"' : '') +
                    (ic.port ? ' port <b>' + esc((ic.switch_name ? ic.switch_name + ' ' : '') + ic.port) + '</b>' : '') : ''],
                ['Seen', esc(h.online ? 'online now' : 'last ' + ago(h.lastSeen)) + (h.firstSeen ? ' <span class="text-muted">first ' + esc(ago(h.firstSeen)) + '</span>' : '')],
                ['Since the connections opened', icon('arrow-down') + ' ' + esc(bytes(st.traffic.received)) + ' &nbsp;' + icon('arrow-up') + ' ' +
                    esc(bytes(st.traffic.sent)) + ' <span class="text-muted">in ' + esc(st.traffic.conns) + ' connections</span>']
            ];
            var conns = drawerData.rows;
            function remoteHtml(ip, port, proto) {
                var name = remoteName(ip);
                return '<span class="nm-r-name">' + esc(name || ip) + '</span><span class="nm-r-port">' + esc(portLabel(proto, port)) + '</span>';
            }
            var connHtml = conns.length ? '<ul class="nm-list">' + $.map(conns.slice(0, 80), function (c) {
                var name = remoteName(c.remote), live = c.up + c.down > 0;
                return '<li class="' + (live ? 'nm-hot' : '') + '"><div class="nm-l1"><span class="nm-dir" title="' +
                    esc(c.outbound ? 'opened by this device' : 'opened towards this device') + '">' +
                    icon(c.outbound ? 'long-arrow-right' : 'long-arrow-left') + '</span>' + remoteHtml(c.remote, c.rport, c.proto) +
                    '<span class="nm-r-rate">' + (live ? icon('arrow-down') + esc(rate(c.down)) + ' ' + icon('arrow-up') + esc(rate(c.up)) : '') + '</span></div>' +
                    '<div class="nm-l2">' + (name ? '<span>' + esc(c.remote) + '</span>' : '') +
                    '<span>' + esc(bytes(c.received)) + ' received, ' + esc(bytes(c.sent)) + ' sent</span>' +
                    (c.rule ? '<span class="nm-rule" title="Firewall rule that allowed it">' + icon('check') + ' ' + esc(c.rule) + '</span>' : '') +
                    '</div></li>';
            }).join('') + '</ul>' + (conns.length > 80 ? '<p class="small text-muted">' + esc(conns.length - 80) + ' more</p>' : '')
                : '<p class="text-muted small">No open connections through the firewall. Traffic to devices on the same network goes ' +
                    'through the switch only and is not seen here.</p>';
            var blk = drawerData.log;
            var blkHtml = blk.length ? '<ul class="nm-list nm-list-blocked">' + $.map(blk.slice(0, 50), function (r) {
                var out = !!h.ips[r.src], remote = out ? r.dst : r.src, name = remoteName(remote);
                return '<li><div class="nm-l1"><span class="nm-dir" title="' + esc(out ? 'from this device' : 'to this device') + '">' +
                    icon(out ? 'long-arrow-right' : 'long-arrow-left') + '</span>' + remoteHtml(remote, r.dstport, r.protoname) +
                    '<span class="nm-r-rate text-muted">' + esc(ago(Date.parse(r.__timestamp__) / 1000)) + '</span></div>' +
                    '<div class="nm-l2">' + (name ? '<span>' + esc(remote) + '</span>' : '') + '<span>' + esc(out ? 'from this device' : 'to this device') +
                    '</span><span class="nm-rule nm-rule-block" title="Firewall rule that blocked it">' + icon('ban') + ' ' +
                    esc(r.label || ('rule ' + r.rulenr)) + (r.rid ? ' <a href="' + esc(logLink('rid', r.rid)) + '" target="_blank" ' +
                    'title="Live log of this rule">' + icon('external-link') + '</a>' : '') + '</span></div></li>';
            }).join('') + '</ul>'
                : '<p class="text-muted small">Nothing blocked in the latest firewall log entries. Only rules with logging enabled ' +
                    '(and the default block rules) are recorded.</p>';
            var nConn = conns.length, nBlk = blk.length;
            if (drawerTab === 'dns' && !opts.adguard) { drawerTab = 'device'; }
            $drawer.find('.nm-dtop').html('<div class="nm-dhead"><span class="nm-ico">' + icon(TYPES[h.type][1]) + '</span><div><h4>' + esc(h.name || h.ip || h.mac) +
                '</h4><small class="text-muted">' + esc(TYPES[h.type][0]) + (h.ip ? ' &middot; ' + esc(h.ip) : '') + '</small></div>' +
                '<button type="button" class="close nm-close" aria-label="Close">&times;</button></div>' +
                '<ul class="nav nav-tabs nm-dtabs">' + $.map(TABS, function (t) {
                    if (t[0] === 'dns' && !opts.adguard) { return ''; }
                    var count = t[0] === 'traffic' ? nConn : (t[0] === 'security' ? nBlk : 0);
                    return '<li' + (drawerTab === t[0] ? ' class="active"' : '') + '><a href="#" data-dtab="' + t[0] + '">' + icon(t[2]) + ' ' + esc(t[1]) +
                        (count ? ' <span class="badge">' + esc(count) + '</span>' : '') + '</a></li>';
                }).join('') + '</ul>');
            $drawer.attr('data-tab', drawerTab);
            $drawer.find('.nm-dlive').html('<div class="nm-dbody">' +
                // Device
                '<div class="nm-pane" data-pane="device"><table class="table table-condensed nm-facts"><tbody>' + $.map(facts, function (f) {
                    return f[1] ? '<tr><th>' + esc(f[0]) + '</th><td>' + f[1] + '</td></tr>' : '';
                }).join('') + '</tbody></table></div>' +
                // Traffic
                '<div class="nm-pane" data-pane="traffic"><h5>Live traffic through the firewall</h5>' + chart() +
                '<h5>Connections <span class="badge">' + esc(nConn) + '</span></h5>' + connHtml +
                '<h5>History <span class="small text-muted">from Insight (NetFlow)</span> <select class="form-control input-sm nm-hist-span">' +
                '<option value="1"' + (histSpan === 1 ? ' selected' : '') + '>last 24 hours</option><option value="7"' + (histSpan === 7 ? ' selected' : '') +
                '>last 7 days</option><option value="30"' + (histSpan === 30 ? ' selected' : '') + '>last 30 days</option></select></h5>' +
                '<div class="nm-hist">' + historyHtml() + '</div></div>' +
                // Security
                '<div class="nm-pane" data-pane="security">' +
                '<h5>Blocked by the firewall <span class="badge">' + esc(nBlk) + '</span>' + (h.ip ? ' <a class="small" href="' +
                    esc(logLink('__addr__', h.ip)) + '" target="_blank">' + icon('external-link') + ' live log</a>' : '') + '</h5>' + blkHtml +
                '<h5>Firewall rules for this device <a class="small" href="/ui/firewall/filter/' + (h.net ? '#interface=' +
                    encodeURIComponent(h.net.id) : '') + '" target="_blank">' + icon('external-link') + ' all rules of ' + esc(h.net ? h.net.name : 'the firewall') +
                    '</a></h5>' + rulesHtml(h) +
                '<h5>Open ports</h5><div class="nm-scan">' + scanHtml(h) + '</div></div>' +
                // DNS
                (opts.adguard ? '<div class="nm-pane" data-pane="dns"><h5>Domains asked <span class="small text-muted">from AdGuard Home</span> ' +
                    '<a href="#" class="small" data-dns-reload>' + icon('refresh') + '</a></h5><div class="nm-dns">' + adguardHtml(h) + '</div></div>' : '') +
                '</div>');
            lookupNames();
        }

        // ---- name, kind and DHCP reservation -------------------------------
        var editing = null;     // 'device' or 'dhcp' while a form is open
        var keaPending = false; // Kea reservations changed but not applied yet

        function kindOptions(current) {
            return '<option value="">automatic (' + esc(TYPES[guessType([selectedHost().autoName], selectedHost().vendor)[0]][0]) + ')</option>' +
                $.map(Object.keys(TYPES).sort(function (a, b) { return TYPES[a][0].localeCompare(TYPES[b][0]); }), function (t) {
                    return '<option value="' + t + '"' + (t === current ? ' selected' : '') + '>' + esc(TYPES[t][0]) + '</option>';
                }).join('');
        }

        function selectedHost() { return model.hosts[selected]; }

        function iconPicker(current) {
            var auto = TYPES[guessType([selectedHost().autoName], selectedHost().vendor)[0]];
            var html = '<label class="nm-icon-opt" title="Automatic: ' + esc(auto[0]) + '"><input type="radio" name="kind" value=""' +
                (current ? '' : ' checked') + '><span>' + icon(auto[1]) + '<small>auto</small></span></label>';
            $.each(Object.keys(TYPES).sort(function (a, b) { return TYPES[a][0].localeCompare(TYPES[b][0]); }), function (_, t) {
                if (t === 'unknown') { return; }
                html += '<label class="nm-icon-opt" title="' + esc(TYPES[t][0]) + '"><input type="radio" name="kind" value="' + t + '"' +
                    (t === current ? ' checked' : '') + '><span>' + icon(TYPES[t][1]) + '<small>' + esc(TYPES[t][0]) + '</small></span></label>';
            });
            return html;
        }

        function field(label, name, value, help, extra) {
            return '<div class="form-group"><label>' + esc(label) + '</label><input type="text" class="form-control input-sm" name="' + name +
                '" value="' + esc(value) + '"' + (extra || '') + '>' + (help ? '<p class="help-block small">' + help + '</p>' : '') + '</div>';
        }

        function renderEdit() {
            var h = selectedHost();
            var $e = $drawer.find('.nm-dedit');
            if (!h || !$e.length) { return; }
            var cu = h.custom || {}, res = h.res, html = '<div class="nm-pane" data-pane="device">';
            if (!h.approved && opts.new_devices) {
                html += '<div class="alert alert-info nm-new-alert">' + icon('star') + ' <b>Not approved yet.</b> ' +
                    (h.firstSeen ? 'First seen ' + esc(ago(h.firstSeen)) + '. ' : '') + 'Approve it if you know it, ban it if you do not.' +
                    '<div class="nm-new-actions"><button type="button" class="btn btn-success btn-xs" data-approve>' + icon('check') + ' Approve</button> ' +
                    '<button type="button" class="btn btn-danger btn-xs" data-fw="banned" data-on="1">' + icon('ban') + ' Ban</button></div></div>';
            }
            if (editing === 'device') {
                html += '<form class="nm-form" data-form="device">' +
                    field('Name in the map', 'name', cu.name || '', 'Leave empty to use ' + (h.autoName ? '"' + esc(h.autoName) + '"' : 'the address') + '.', ' maxlength="64"') +
                    '<div class="form-group"><label>Icon and kind</label><div class="nm-icons">' + iconPicker(cu.kind || '') + '</div></div>' +
                    field('Group', 'group', cu.group || '', 'For example Kids, Untrusted IoT or Guests: the map can then filter and block a whole group.',
                        ' maxlength="32" list="nm-groups"') + '<datalist id="nm-groups">' + $.map(groupNames(), function (g) {
                            return '<option value="' + esc(g) + '">';
                        }).join('') + '</datalist>' +
                    field('Notes', 'notes', cu.notes || '', '', ' maxlength="256"') +
                    '<button type="submit" class="btn btn-success btn-xs">Save</button> <button type="button" class="btn btn-default btn-xs" data-cancel>Cancel</button></form>';
            } else {
                html += '<div class="nm-edit-row"><div><b>' + esc(h.name || h.ip) + '</b> <span class="text-muted small">' + esc(TYPES[h.type][0]) +
                    (h.typeSource ? ', from ' + esc(h.typeSource) : '') + '</span>' + (cu.notes ? '<div class="small">' + esc(cu.notes) + '</div>' : '') +
                    '</div><span>' + (h.net ? '<button type="button" class="btn btn-default btn-xs" data-wake title="Send a Wake-on-LAN packet ' +
                    '(the device must support it and be connected by cable)">' + icon('power-off') + ' Wake</button> ' : '') +
                    '<button type="button" class="btn btn-default btn-xs" data-edit="device">' + icon('pencil') + ' Rename</button></span></div>';
            }
            var subnet = h.ip ? model.keaSubnetOf(h.ip) : null;
            html += '<div class="nm-dhcp"><h5>DHCP (Kea)</h5>';
            if (editing === 'dhcp') {
                html += '<form class="nm-form" data-form="dhcp">' +
                    field('IP address', 'ip_address', res ? res.ip_address : h.ip, subnet ? 'In ' + esc(subnet.cidr) + (subnet.name ? ' (' + esc(subnet.name) + ')' : '') + '.' : '') +
                    field('Hostname', 'hostname', res ? res.hostname : (h.lease && h.lease.hostname) || '', 'Letters, digits and hyphens; sent to the device and used for DNS registration.') +
                    field('Description', 'description', res ? res.description : (cu.name || h.autoName || ''), '') +
                    '<button type="submit" class="btn btn-success btn-xs">' + (res ? 'Save reservation' : 'Create reservation') + '</button> ' +
                    '<button type="button" class="btn btn-default btn-xs" data-cancel>Cancel</button></form>';
            } else if (res) {
                html += '<div class="nm-edit-row"><div>' + icon('lock') + ' Reserved <b>' + esc(res.ip_address || 'any address') + '</b>' +
                    (res.hostname ? ' as <b>' + esc(res.hostname) + '</b>' : '') + (res.description ? '<div class="small text-muted">' + esc(res.description) + '</div>' : '') +
                    '</div><span><button type="button" class="btn btn-default btn-xs" data-edit="dhcp">' + icon('pencil') + ' Edit</button> ' +
                    '<button type="button" class="btn btn-default btn-xs" data-dhcp-del>' + icon('trash') + '</button></span></div>';
            } else if (subnet) {
                html += '<div class="nm-edit-row"><div class="small">' + (h.lease ? 'Dynamic lease' + (h.lease.hostname ? ' as <b>' + esc(h.lease.hostname) + '</b>' : '') +
                    (h.lease.expire ? ', expires ' + esc(new Date(h.lease.expire * 1000).toLocaleString()) : '') : 'No lease seen') +
                    '</div><button type="button" class="btn btn-default btn-xs" data-edit="dhcp">' + icon('lock') + ' Reserve this address</button></div>';
            } else {
                html += '<p class="small text-muted">Kea has no subnet for ' + esc(h.net ? h.net.name : 'this network') + ': the address is static ' +
                    'or given by another DHCP server.</p>';
            }
            if (keaPending) {
                html += '<div class="alert alert-info nm-apply">' + icon('info-circle') + ' Reservation changes are saved but Kea does not use them yet. ' +
                    '<button type="button" class="btn btn-success btn-xs" data-kea-apply>Apply</button></div>';
            }
            html += '<div class="nm-edit-msg"></div></div></div><div class="nm-pane" data-pane="security">' + fwHtml(h) + '</div>';
            $e.html(html);
        }

        function editMessage(kind, text) {
            $drawer.find('.nm-edit-msg').html('<div class="alert alert-' + kind + ' small">' + text + '</div>');
        }

        function failure(r) {
            if (r && r.validations) { return $.map(r.validations, function (v) { return esc(v); }).join('<br>'); }
            return esc((r && (r.message || r.errorMessage)) || 'the change was refused');
        }

        function afterSave() {
            editing = null;
            return loadHosts().always(function () { renderEdit(); renderDrawer(); draw(); });
        }

        $drawer.on('click', '[data-edit]', function () { editing = $(this).data('edit'); renderEdit(); });
        $drawer.on('click', '[data-cancel]', function () { editing = null; renderEdit(); });
        $drawer.on('click', '[data-wake]', function () {
            var h = selectedHost(), $b = $(this).prop('disabled', true);
            call('wol/wol/set', {wake: {interface: h.net.id, mac: h.mac}}).done(function () {
                editMessage('success', 'Wake-on-LAN packet sent to ' + esc(h.mac) + ' on ' + esc(h.net.name) + '.');
            }).fail(function (err) {
                editMessage('danger', err && err.status === 404 ? 'The Wake-on-LAN plugin (os-wol) is not installed.' : esc(why(err)));
            }).always(function () { $b.prop('disabled', false); });
        });
        $drawer.on('submit', '.nm-form', function (e) {
            e.preventDefault();
            var h = selectedHost(), v = {};
            $(this).serializeArray().forEach(function (f) { v[f.name] = $.trim(f.value); });
            var $btn = $(this).find('[type=submit]').prop('disabled', true);
            var req;
            if ($(this).data('form') === 'forward') { addForward(h, v, $btn); return; }
            if ($(this).data('form') === 'device') {
                req = search('netmap/devices/save', {mac: h.mac, name: v.name, kind: v.kind, notes: v.notes, group: v.group});
            } else if (h.res) {
                req = search('kea/dhcpv4/set_reservation/' + encodeURIComponent(h.res.uuid),
                    {reservation: {ip_address: v.ip_address, hostname: v.hostname, description: v.description}});
            } else {
                var subnet = model.keaSubnetOf(v.ip_address || h.ip);
                if (!subnet) { editMessage('danger', 'The address is not in a Kea subnet.'); $btn.prop('disabled', false); return; }
                req = search('kea/dhcpv4/add_reservation', {reservation: {subnet: subnet.uuid, ip_address: v.ip_address, hw_address: h.mac,
                    hostname: v.hostname, description: v.description}});
            }
            var isDhcp = $(this).data('form') === 'dhcp';
            req.done(function (r) {
                if (r && (r.result === 'saved' || r.result === 'deleted')) {
                    if (isDhcp) { keaPending = true; }
                    afterSave();
                } else {
                    editMessage('danger', failure(r));
                    $btn.prop('disabled', false);
                }
            }).fail(function (xhr) {
                editMessage('danger', xhr.status === 403 ? 'Your account may not make this change.' : 'HTTP ' + esc(xhr.status));
                $btn.prop('disabled', false);
            });
        });
        $drawer.on('click', '[data-dhcp-del]', function () {
            var h = selectedHost();
            if (!h || !h.res) { return; }
            var $b = $(this);
            if (!$b.data('armed')) {
                $b.data('armed', true).addClass('btn-danger').html(icon('trash') + ' Delete reservation?');
                return;
            }
            search('kea/dhcpv4/del_reservation/' + encodeURIComponent(h.res.uuid), {}).done(function (r) {
                if (r && r.result === 'deleted') { keaPending = true; afterSave(); } else { editMessage('danger', failure(r)); }
            });
        });
        $drawer.on('click', '[data-kea-apply]', function () {
            var $b = $(this).prop('disabled', true).html(icon('spinner fa-pulse') + ' Applying...');
            search('kea/service/reconfigure', {}).done(function (r) {
                keaPending = false;
                renderEdit();
                editMessage(r && r.status === 'ok' ? 'success' : 'warning', r && r.status === 'ok' ? 'Kea uses the new reservations.' :
                    'Kea answered: ' + esc(JSON.stringify(r)));
            }).fail(function (xhr) {
                $b.prop('disabled', false).text('Apply');
                editMessage('danger', 'HTTP ' + esc(xhr.status));
            });
        });

        // ---- firewall: ban, Internet block, port forwards ----------------
        // Blocking uses MAC address aliases, so a device stays blocked when its address changes.
        // The two rules are created once, the first time they are needed; afterwards banning and
        // unbanning only change the alias content.
        var FW = {
            banned: {alias: 'netmap_banned', rule: 'Network Map: block banned devices', label: 'banned'},
            nowan: {alias: 'netmap_nowan', rule: 'Network Map: block Internet access', label: 'without Internet'}
        };
        var PRIVATE_ALIAS = 'netmap_private';
        var fwBusy = false;

        function splitContent(c) {
            if ($.isPlainObject(c)) { return $.map(c, function (v, k) { return v && v.selected ? k : null; }); }
            return $.grep(String(c || '').split(/[\s,]+/), Boolean);
        }

        function loadFirewall() {
            var none = function () { return $.Deferred().resolve([{rows: []}]); };
            return $.when(
                search('firewall/alias/search_item', {current: 1, rowCount: -1, searchPhrase: ''}).then(null, none),
                search('firewall/filter/search_rule', {current: 1, rowCount: -1, searchPhrase: ''}).then(null, none),
                search('firewall/d_nat/search_rule', {current: 1, rowCount: -1, searchPhrase: ''}).then(null, none),
                get('firewall/filter/get_rule').then(null, function () { return $.Deferred().resolve([{}]); })
            ).then(function (a, r, d, tpl) {
                var fw = {aliases: {}, rules: {}, byDesc: {}, forwards: [], ruleList: [], schedules: []};
                $.each(((tpl[0] || {}).rule || {}).sched || {}, function (name) { if (name) { fw.schedules.push(name); } });
                $.each((a[0] || {}).rows || [], function (_, x) {
                    var raw = splitContent(x.content);
                    fw.aliases[x.name] = {uuid: x.uuid, type: x.type, raw: raw, content: $.map(raw, normMac)};
                });
                $.each((r[0] || {}).rows || [], function (_, x) {
                    $.each(FW, function (key, def) { if (x.description === def.rule) { fw.rules[key] = x.uuid; } });
                    if (x.description) { fw.byDesc[x.description] = x.uuid; }
                    // rules generated by OPNsense itself cannot be toggled and are left out
                    if (!x.legacy && !x.is_automatic) { fw.ruleList.push(x); }
                });
                $.each((d[0] || {}).rows || [], function (_, x) {
                    if (String(x.uuid).indexOf('automatic') === 0) { return; }
                    fw.forwards.push({uuid: x.uuid, iface: x['%interface'] || x.interface, proto: x.protocol, port: x['destination.port'],
                        target: x.target, localPort: x['local-port'], descr: x.descr, disabled: x.disabled === '1',
                        wan: x.interface === model.wanIf});
                });
                model.fw = fw;
                return $.Deferred().resolve();
            });
        }

        // FW entries, plus one entry per schedule: "sched:<name>" blocks Internet during that schedule
        function defOf(key) {
            if (FW[key]) { return FW[key]; }
            var name = key.slice(6);
            return {alias: 'netmap_s_' + name.replace(/[^A-Za-z0-9_]/g, '_').slice(0, 22), sched: name,
                rule: 'Network Map: block Internet during ' + name, label: 'without Internet during ' + name};
        }

        function isMember(key, mac) {
            var a = model.fw.aliases[defOf(key).alias];
            return !!(a && a.content.indexOf(mac) >= 0);
        }

        function call(path, body) {
            return search(path, body || {}).then(function (r) {
                if (r && (r.result === 'failed' || r.status === 'failed')) {
                    return $.Deferred().reject({responseJSON: r});
                }
                return r;
            });
        }

        function why(err) {
            var r = err && (err.responseJSON || err);
            if (r && r.validations) { return $.map(r.validations, function (v, k) { return k + ': ' + v; }).join('; '); }
            if (err && err.status === 403) { return 'your account may not change the firewall'; }
            return (r && (r.message || r.errorMessage)) || (err && err.status ? 'HTTP ' + err.status : 'the firewall refused the change');
        }

        // create the alias(es) and rule for ``key`` when they do not exist yet
        function ensureRule(key) {
            var def = defOf(key);
            if (model.fw.byDesc[def.rule]) { return $.Deferred().resolve(false); }
            var steps = $.Deferred().resolve();
            if (key !== 'banned' && !model.fw.aliases[PRIVATE_ALIAS]) {
                steps = steps.then(function () {
                    return call('firewall/alias/add_item', {alias: {enabled: '1', name: PRIVATE_ALIAS, type: 'network',
                        content: '10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n100.64.0.0/10',
                        description: 'Network Map: private networks (not the Internet)'}});
                });
            }
            var interfaces = $.map(model.nets, function (n) { return n.id; }).join(',');
            var rule = key === 'banned'
                ? {enabled: '1', action: 'block', quick: '1', interface: interfaces, direction: 'in', ipprotocol: 'inet46', protocol: 'any',
                    source_net: FW.banned.alias, destination_net: 'any', sequence: '1', log: '1', description: FW.banned.rule}
                : {enabled: '1', action: 'block', quick: '1', interface: interfaces, direction: 'in', ipprotocol: 'inet', protocol: 'any',
                    source_net: def.alias, destination_net: PRIVATE_ALIAS, destination_not: '1', sequence: def.sched ? '3' : '2', log: '1',
                    sched: def.sched || '', description: def.rule};
            return steps.then(function () { return call('firewall/filter/add_rule', {rule: rule}); })
                .then(function () { return true; });
        }

        function applyRules() {
            // OPNsense 26.x has no savepoint endpoint any more: the new rules are applied directly.
            // They only block traffic from the devices in the aliases, and the automatic anti-lockout
            // rule keeps the web interface reachable.
            return call('firewall/filter/apply');
        }

        function setMember(key, mac, on) { return setMembers(key, [mac], on); }

        function setMembers(key, macs, on) {
            var def = defOf(key), a = model.fw.aliases[def.alias];
            var list = $.grep(a ? a.content : [], function (m) { return macs.indexOf(m) < 0; });
            if (on) { list = list.concat(macs); }
            var content = list.join('\n');
            var created = false;
            var save = a ? call('firewall/alias/set_item/' + encodeURIComponent(a.uuid), {alias: {content: content}})
                : call('firewall/alias/add_item', {alias: {enabled: '1', name: def.alias, type: 'mac', content: content,
                    description: 'Network Map: devices ' + def.label}});
            return save.then(function () { return on ? ensureRule(key) : false; })
                .then(function (made) { created = made; return call('firewall/alias/reconfigure'); })
                .then(function () { return created ? applyRules() : null; });
        }

        function forwardsOf(h) {
            return $.grep(model.fw.forwards, function (f) { return h.ips[f.target]; });
        }

        function fwHtml(h) {
            if (!opts.firewall_actions) { return ''; }
            var html = '<div class="nm-fw-sec"><h5>Firewall</h5>';
            $.each([['banned', 'Network access', 'blocked: no traffic through the firewall (Internet, other networks, firewall services)',
                'allowed', 'Ban', 'Unban'],
                ['nowan', 'Internet access', 'blocked: local networks only', 'allowed', 'Block Internet', 'Allow Internet']], function (_, x) {
                var on = isMember(x[0], h.mac);
                html += '<div class="nm-edit-row nm-fw-row"><button type="button" class="btn btn-xs ' +
                    (on ? 'btn-success' : (x[0] === 'banned' ? 'btn-danger' : 'btn-warning')) + '" data-fw="' + x[0] + '" data-on="' + (on ? 0 : 1) + '">' +
                    icon(on ? 'unlock' : 'ban') + ' ' + esc(on ? x[5] : x[4]) + '</button><div><b>' + esc(x[1]) + ':</b> ' +
                    (on ? '<span class="text-danger">' + esc(x[2]) + '</span>' : '<span class="text-success">' + esc(x[3]) + '</span>') + '</div></div>';
            });
            var scheds = model.fw.schedules || [];
            var active = $.grep(scheds, function (n) { return isMember('sched:' + n, h.mac); });
            html += '<div class="nm-fw-sched"><b>Internet on a schedule</b> ';
            $.each(active, function (_, n) {
                html += '<div class="nm-edit-row nm-fw-row"><button type="button" class="btn btn-xs btn-success" data-fw="sched:' + esc(n) +
                    '" data-on="0">' + icon('unlock') + ' Remove</button><div>No Internet during <b>' + esc(n) + '</b></div></div>';
            });
            var free = $.grep(scheds, function (n) { return active.indexOf(n) < 0; });
            if (free.length) {
                html += '<div class="nm-edit-row nm-fw-row"><button type="button" class="btn btn-xs btn-warning" data-sched-add>' + icon('clock-o') +
                    ' Block during</button><select class="form-control input-sm nm-sched-pick">' + $.map(free, function (n) {
                        return '<option value="' + esc(n) + '">' + esc(n) + '</option>';
                    }).join('') + '</select></div>';
            } else if (!scheds.length) {
                html += '<span class="small text-muted">No schedules yet: create one (for example "Night", 22:00 to 07:00) in ' +
                    '<a href="/firewall_schedule.php" target="_blank">Firewall &gt; Settings &gt; Schedules</a>.</span>';
            }
            html += '</div>';
            var fwd = forwardsOf(h);
            html += '<div class="nm-fw-fwd"><b>Port forwards</b>' + (fwd.length ? '<ul class="nm-list">' + $.map(fwd, function (f) {
                return '<li><div class="nm-l1"><span class="nm-r-name">' + esc(String(f.proto).toUpperCase() + ' ' + f.port) + '</span>' +
                    '<span class="nm-r-port">' + icon('long-arrow-right') + ' ' + esc(f.target + ':' + (f.localPort || f.port)) + '</span>' +
                    (f.disabled ? '<span class="label label-default">disabled</span>' : '') +
                    '<span class="nm-r-rate"><button type="button" class="btn btn-default btn-xs" data-fwd-del="' + esc(f.uuid) + '" title="Delete">' +
                    icon('trash') + '</button></span></div><div class="nm-l2"><span>' + esc(f.iface) + '</span><span>' + esc(f.descr || '') + '</span></div></li>';
            }).join('') + '</ul>' : ' <span class="text-muted small">none</span>');
            if (editing === 'forward') {
                html += '<form class="nm-form" data-form="forward"><div class="nm-form-row">' +
                    '<div class="form-group"><label>Protocol</label><select class="form-control input-sm" name="protocol"><option value="tcp">TCP</option>' +
                    '<option value="udp">UDP</option><option value="tcp/udp">TCP and UDP</option></select></div>' +
                    field('Internet port', 'port', '', 'A port or a range, e.g. 8443 or 5000-5010.') +
                    field('Device port', 'local_port', '', 'Empty: the same port.') + '</div>' +
                    field('Description', 'descr', 'Network Map: ' + (h.name || h.ip), '') +
                    (h.res ? '' : '<p class="small text-warning">' + icon('exclamation-triangle') + ' The address ' + esc(h.ip) + ' is not reserved: ' +
                        'the forward stops working when the device gets another address. Reserve it in the DHCP section first.</p>') +
                    '<p class="small text-muted">Connections from the Internet to the firewall on this port reach ' + esc(h.ip) +
                    '. The forward is created on the WAN interface and passes its traffic without a separate rule.</p>' +
                    '<button type="submit" class="btn btn-success btn-xs">Create port forward</button> ' +
                    '<button type="button" class="btn btn-default btn-xs" data-cancel>Cancel</button></form>';
            } else {
                html += '<div><button type="button" class="btn btn-default btn-xs" data-edit="forward"' + (model.wanIf ? '' : ' disabled') + '>' +
                    icon('plus') + ' Add port forward</button></div>';
            }
            return html + '</div><div class="nm-fw-msg"></div></div>';
        }

        function fwMessage(kind, text) {
            $drawer.find('.nm-fw-msg').html('<div class="alert alert-' + kind + ' small">' + text + '</div>');
        }

        function fwDone(text) {
            fwBusy = false;
            return loadFirewall().always(function () { renderEdit(); draw(); fwMessage('success', esc(text)); });
        }

        // confirmation dialog (Bootstrap 3 modal); resolves when the user confirms
        function confirmDialog(title, body, okLabel, danger) {
            var done = $.Deferred();
            var $m = $('<div class="modal fade nm-modal" tabindex="-1" role="dialog"><div class="modal-dialog" role="document">' +
                '<div class="modal-content"><div class="modal-header"><button type="button" class="close" data-dismiss="modal" aria-label="Close">' +
                '&times;</button><h4 class="modal-title">' + esc(title) + '</h4></div><div class="modal-body">' + body + '</div>' +
                '<div class="modal-footer"><button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>' +
                '<button type="button" class="btn btn-' + (danger ? 'danger' : 'success') + ' nm-modal-ok">' + esc(okLabel) + '</button>' +
                '</div></div></div></div>');
            $m.find('.nm-modal-ok').on('click', function () { done.resolve(); $m.modal('hide'); });
            $m.on('hidden.bs.modal', function () { if (done.state() === 'pending') { done.reject(); } $m.remove(); });
            // above the device panel, which itself sits above the OPNsense header
            $m.on('shown.bs.modal', function () { $('.modal-backdrop').last().css('z-index', 2090); $m.find('.nm-modal-ok').trigger('focus'); });
            $('body').append($m);
            $m.modal('show');
            return done.promise();
        }

        function fwDialog(key, on, h) {
            h = h || {};
            var def = defOf(key), title, ok, points;
            var device = '<div class="nm-modal-device"><span class="nm-ico" style="--net:' + (h.net ? h.net.color : '#888') + '">' +
                icon(TYPES[h.type] ? TYPES[h.type][1] : 'question') + '</span><div><b>' + esc(h.name || h.ip || h.mac || '') + '</b>' +
                '<small>' + esc([h.ip, h.mac, h.net ? h.net.name : ''].filter(Boolean).join(' · ')) + '</small></div></div>';
            if (def.sched) {
                title = on ? 'Block Internet on a schedule' : 'Remove the scheduled block';
                ok = on ? 'Block during ' + def.sched : 'Remove';
                points = on ? ['Connections to the Internet are blocked while the schedule "' + def.sched + '" is active.',
                    'Outside the schedule, and towards the local networks, nothing changes.']
                    : ['The schedule "' + def.sched + '" no longer limits its Internet access.'];
            } else if (key === 'banned') {
                title = on ? 'Ban this device' : 'Unban this device';
                ok = on ? 'Ban' : 'Unban';
                points = on ? ['All its traffic through the firewall is blocked: Internet, the other networks and the services of the ' +
                    'firewall such as DNS and NTP.', 'Devices on the same network can still reach it, because that traffic only goes ' +
                    'through the switch.', 'The block follows the MAC address, also when the device gets another IP address.']
                    : ['Its traffic through the firewall is allowed again, as set by your other rules.'];
            } else {
                title = on ? 'Block Internet access' : 'Allow Internet access';
                ok = on ? 'Block Internet' : 'Allow Internet';
                points = on ? ['Connections to the Internet are blocked.', 'The device can still reach the local networks and the ' +
                    'firewall, for example DNS and its controller in the house.', 'The block follows the MAC address, also when the ' +
                    'device gets another IP address.']
                    : ['Connections to the Internet are allowed again, as set by your other rules.'];
            }
            var body = device + '<ul class="nm-modal-points">' + $.map(points, function (p) { return '<li>' + esc(p) + '</li>'; }).join('') + '</ul>';
            if (on && key === 'banned') {
                body += '<div class="alert alert-warning nm-modal-note">' + icon('exclamation-triangle') + ' Do not ban the computer you are using.</div>';
            }
            if (on && !model.fw.byDesc[defOf(key).rule]) {
                body += '<div class="alert alert-info nm-modal-note">' + icon('info-circle') + ' <b>First use.</b> The firewall rule "' +
                    esc(def.rule) + '" is created on every internal network and the rules are applied. Afterwards this action only ' +
                    'updates the alias <code>' + esc(def.alias) + '</code>.</div>';
            }
            return confirmDialog(title, body, ok, on);
        }

        $drawer.on('click', '[data-sched-add]', function () {
            var name = $drawer.find('.nm-sched-pick').val();
            if (name) { $(this).attr('data-fw', 'sched:' + name).attr('data-on', '1').removeAttr('data-sched-add').trigger('click'); }
        });

        $drawer.on('click', '[data-fw]', function () {
            var h = selectedHost(), key = $(this).data('fw'), on = $(this).data('on') === 1, $b = $(this);
            if (!h || fwBusy) { return; }
            fwDialog(key, on, h).done(function () {
                fwBusy = true;
                $b.prop('disabled', true).html(icon('spinner fa-pulse') + ' Applying...');
                setMember(key, h.mac, on).done(function () {
                    fwDone((h.name || h.ip) + (on ? ' is now ' : ' is no longer ') + defOf(key).label + '.');
                }).fail(function (err) {
                    fwBusy = false;
                    renderEdit();
                    fwMessage('danger', esc(why(err)));
                });
            });
        });
        $drawer.on('click', '[data-fwd-del]', function () {
            var $b = $(this), uuid = $b.data('fwd-del');
            if (!$b.data('armed')) { $b.data('armed', true).addClass('btn-danger').html(icon('trash') + ' Delete?'); return; }
            $b.prop('disabled', true);
            call('firewall/d_nat/del_rule/' + encodeURIComponent(uuid)).then(function () { return call('firewall/d_nat/apply'); })
                .done(function () { fwDone('Port forward deleted.'); })
                .fail(function (err) { fwMessage('danger', esc(why(err))); $b.prop('disabled', false); });
        });

        function addForward(h, v, $btn) {
            if (!/^\d{1,5}(-\d{1,5})?$/.test(v.port) || (v.local_port && !/^\d{1,5}$/.test(v.local_port))) {
                fwMessage('danger', 'Use a port number or a range such as 5000-5010.');
                $btn.prop('disabled', false);
                return;
            }
            call('firewall/d_nat/add_rule', {rule: {disabled: '0', interface: model.wanIf, ipprotocol: 'inet', protocol: v.protocol,
                destination: {network: model.wanIf + 'ip', port: v.port}, target: h.ip,
                'local-port': v.local_port || v.port.split('-')[0], descr: v.descr, pass: 'pass'}})
                .then(function () { return call('firewall/d_nat/apply'); })
                .done(function () { editing = null; fwDone('Port forward created.'); })
                .fail(function (err) { fwMessage('danger', esc(why(err))); $btn.prop('disabled', false); });
        }

        // ---- firewall rules that concern a device ---------------------------
        var IFACE_RE = /^(lan|wan|opt\d+)$/;

        // does an address field of a rule cover this device? true, false or null when it cannot be told
        function covers(spec, h, depth) {
            spec = String(spec || '').trim();
            if (!spec || spec === 'any') { return true; }
            if (IFACE_RE.test(spec)) { return !!(h.net && h.net.id === spec); }
            if (/^(lan|wan|opt\d+)ip$/.test(spec) || spec === '(self)' || spec === 'This Firewall') { return false; }
            if (/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(spec)) {
                var cidr = spec.indexOf('/') > 0 ? spec : spec + '/32';
                return Object.keys(h.ips).some(function (ip) { return inCidr(ip, cidr); });
            }
            if (spec.indexOf(':') >= 0) { return false; }  // IPv6 literal: the map tracks IPv4 only
            var a = model.fw.aliases[spec];
            if (!a || (depth || 0) > 4) { return null; }
            if (a.type === 'mac') { return a.content.indexOf(h.mac) >= 0; }
            if (a.type === 'host' || a.type === 'network' || a.type === 'networkgroup') {
                var unknown = false;
                for (var i = 0; i < a.raw.length; i++) {
                    var r = covers(a.raw[i], h, (depth || 0) + 1);
                    if (r === true) { return true; }
                    if (r === null && !/^\d/.test(a.raw[i])) { unknown = true; }  // host names, nested aliases of other kinds
                }
                return unknown ? null : false;
            }
            return null;  // GeoIP, URL tables, dynamic aliases: not resolvable here
        }

        function rulesFor(h) {
            var out = [];
            if (!h || !h.ip) { return out; }
            $.each(model.fw.ruleList || [], function (i, x) {
                var ifaces = $.grep(String(x.interface || '').split(','), Boolean);
                var onIface = !ifaces.length || (h.net && ifaces.indexOf(h.net.id) >= 0);
                if (x.interfacenot === '1') { onIface = !onIface; }
                var src = covers(x.source_net, h), dst = covers(x.destination_net, h);
                if (x.source_not === '1' && src !== null) { src = !src; }
                if (x.destination_not === '1' && dst !== null) { dst = !dst; }
                var from = onIface && x.direction !== 'out' && src !== false;
                var to = String(x.destination_net || 'any') !== 'any' && x.destination_not !== '1' && dst === true;
                if (from || to) {
                    out.push({rule: x, order: i + 1, from: from, to: to && !from, maybe: (from && src === null) || (to && dst === null)});
                }
            });
            return out;
        }

        function ruleHits(x, h) {
            var conns = $.grep(drawerData.rows, function (c) { return c.rule && c.rule === x.description; }).length;
            var blocks = $.grep(drawerData.log, function (r) { return r.rid === x.uuid || (r.label && r.label === x.description); }).length;
            return {conns: conns, blocks: blocks};
        }

        function rulesHtml(h) {
            var list = rulesFor(h);
            if (!model.fw.ruleList || !model.fw.ruleList.length) {
                return '<p class="text-muted small">The firewall rules cannot be read with your privileges.</p>';
            }
            if (!list.length) { return '<p class="text-muted small">No rule names this device or its network.</p>'; }
            return '<ul class="nm-list nm-rules">' + $.map(list, function (it) {
                var x = it.rule, hits = ruleHits(x, h), on = x.enabled === '1';
                var act = x.action === 'pass' ? ['success', 'pass'] : (x.action === 'reject' ? ['warning', 'reject'] : ['danger', 'block']);
                var src = (x.source_not === '1' ? 'not ' : '') + (x['%source_net'] || x.source_net || 'any');
                var dst = (x.destination_not === '1' ? 'not ' : '') + (x['%destination_net'] || x.destination_net || 'any') +
                    (x.destination_port ? ' : ' + x.destination_port : '');
                var link = '/ui/firewall/filter/#' + (h.net ? 'interface=' + encodeURIComponent(h.net.id) + '&' : '') +
                    'search=' + encodeURIComponent(x.description || '');
                return '<li class="' + (on ? '' : 'nm-rule-off') + '"><div class="nm-l1">' +
                    (!opts.firewall_actions ? '' : '<label class="nm-switch" title="' + (on ? 'Disable' : 'Enable') + ' this rule"><input type="checkbox" data-rule-toggle="' +
                    esc(x.uuid) + '"' + (on ? ' checked' : '') + '><span></span></label>') +
                    '<span class="label label-' + act[0] + '">' + act[1] + '</span>' +
                    '<a class="nm-r-name" href="' + esc(link) + '" target="_blank" title="Open in Firewall > Rules">' +
                    esc(x.description || ('rule ' + it.order)) + ' ' + icon('external-link') + '</a>' +
                    '<span class="nm-r-rate small">' + (hits.conns ? '<span class="text-success" title="Open connections allowed by this rule">' +
                    esc(hits.conns) + ' conn.</span> ' : '') + (hits.blocks ? '<span class="text-danger" title="Recent packets blocked by this rule">' +
                    icon('ban') + esc(hits.blocks) + '</span>' : '') + '</span></div>' +
                    '<div class="nm-l2"><span>' + esc(it.from ? 'from this device' : 'to this device') + '</span><span>' + esc(src) + ' ' +
                    icon('long-arrow-right') + ' ' + esc(dst) + '</span><span>' + esc(String(x.protocol || 'any').toUpperCase()) + '</span>' +
                    (it.maybe ? '<span class="text-warning" title="The rule uses an alias that cannot be resolved here (GeoIP, URL, host names)">' +
                    'may apply</span>' : '') + '</div></li>';
            }).join('') + '</ul>';
        }

        $drawer.on('change', '[data-rule-toggle]', function () {
            var $c = $(this), uuid = $c.data('rule-toggle'), enable = this.checked;
            var x = $.grep(model.fw.ruleList, function (r) { return r.uuid === uuid; })[0] || {};
            $c.prop('checked', !enable);  // unchanged until confirmed
            confirmDialog(enable ? 'Enable firewall rule' : 'Disable firewall rule',
                '<p>' + (enable ? 'Enable' : 'Disable') + ' the rule <b>' + esc(x.description || uuid) + '</b>?</p>' +
                '<ul class="nm-modal-points"><li>The change applies to every device the rule matches, not only to this one.</li>' +
                '<li>The firewall rules are applied at once.</li></ul>', enable ? 'Enable rule' : 'Disable rule', !enable)
                .done(function () {
                    $c.prop('disabled', true);
                    call('firewall/filter/toggle_rule/' + encodeURIComponent(uuid) + '/' + (enable ? '1' : '0'))
                        .then(function () { return call('firewall/filter/apply'); })
                        .done(function () { loadFirewall().always(function () { renderDrawer(); }); })
                        .fail(function (err) { $c.prop('disabled', false); fwMessage('danger', esc(why(err))); });
                });
        });

        // ---- DNS from AdGuard Home ------------------------------------------
        function loadAdguard() {
            var h = selectedHost();
            if (!opts.adguard || !h || !h.ip) { return; }
            var mac = selected;
            drawerData.dns = {loading: true};
            get('netmap/adguard/queries/' + encodeURIComponent(h.ip)).done(function (d) {
                if (selected === mac) { drawerData.dns = d || {}; renderDrawer(); }
            }).fail(function (xhr) {
                if (selected === mac) { drawerData.dns = {status: 'error', message: 'HTTP ' + xhr.status}; renderDrawer(); }
            });
        }

        function adguardHtml(h) {
            var d = drawerData.dns;
            if (!d || d.loading) { return '<p class="small text-muted">' + icon('spinner fa-pulse') + ' asking AdGuard Home...</p>'; }
            if (d.status !== 'ok') { return '<p class="small text-danger">' + icon('exclamation-triangle') + ' ' + esc(d.message || 'no answer') + '</p>'; }
            var html = '<div class="nm-edit-row nm-fw-row">' + (d.dns_blocked
                ? '<button type="button" class="btn btn-xs btn-success" data-dns-block="0">' + icon('unlock') + ' Allow DNS</button>' +
                  '<div><b>DNS:</b> <span class="text-danger">blocked in AdGuard Home</span></div>'
                : '<button type="button" class="btn btn-xs btn-warning" data-dns-block="1">' + icon('ban') + ' Block DNS</button>' +
                  '<div><b>DNS:</b> <span class="text-success">answered</span></div>') + '</div>';
            html += '<p class="small">' + esc(d.total) + ' queries in the latest log entries, <span class="' + (d.blocked ? 'text-danger' : '') + '">' +
                esc(d.blocked) + ' blocked</span>' + (d.since ? ' <span class="text-muted">since ' + esc(new Date(d.since).toLocaleString()) + '</span>' : '') + '</p>';
            if (!(d.domains || []).length) { return html + '<p class="small text-muted">No queries from this address in the AdGuard Home log.</p>'; }
            var max = Math.max.apply(null, $.map(d.domains, function (x) { return x.count; }));
            return html + '<ul class="nm-list nm-dns-list">' + $.map(d.domains, function (x) {
                var ur = x.user_rule, btn;
                if (ur) {
                    btn = '<span class="label label-' + (ur.action === 'block' ? 'danger' : 'success') + '" title="Your custom rule in AdGuard Home">' +
                        esc(ur.action === 'block' ? 'blocked by you' : 'allowed by you') + (ur.scope === 'all' ? ', whole network' : '') + '</span> ' +
                        '<button type="button" class="btn btn-default btn-xs" data-dns-rule="remove" data-scope="' + ur.scope + '" data-domain="' +
                        esc(x.name) + '" title="Remove your rule">' + icon('undo') + '</button>';
                } else if (x.blocked) {
                    btn = '<button type="button" class="btn btn-success btn-xs" data-dns-rule="allow" data-domain="' + esc(x.name) + '">' +
                        icon('check') + ' Allow</button>';
                } else {
                    btn = '<button type="button" class="btn btn-warning btn-xs" data-dns-rule="block" data-domain="' + esc(x.name) + '">' +
                        icon('ban') + ' Block</button>';
                }
                return '<li><div class="nm-l1"><span class="nm-r-name">' + esc(x.name) + '</span>' +
                    (x.blocked && !ur ? '<span class="label label-danger">blocked</span>' : '') + '<span class="nm-r-rate small">' + esc(x.count) +
                    ' &nbsp;' + btn + '</span></div>' +
                    '<div class="nm-hbar"><i style="width:' + Math.max(2, Math.round(x.count * 100 / max)) + '%' + (x.blocked ? ';background:#c4473b' : '') + '"></i></div>' +
                    (x.rule ? '<div class="nm-l2"><span class="nm-rule nm-rule-block">' + icon('ban') + ' ' + esc(x.rule) + '</span></div>' : '') + '</li>';
            }).join('') + '</ul>';
        }

        // block or allow one domain with a custom rule in AdGuard Home, for this device or the whole network
        $drawer.on('click', '[data-dns-rule]', function () {
            var h = selectedHost(), action = $(this).data('dns-rule'), domain = $(this).data('domain');
            var scopeFixed = $(this).data('scope');
            var body = '<p>' + (action === 'remove' ? 'Remove your AdGuard Home rule for <b>' + esc(domain) + '</b>?'
                : (action === 'block' ? 'Block' : 'Allow') + ' <b>' + esc(domain) + '</b> in AdGuard Home?') + '</p>';
            if (action !== 'remove') {
                body += '<div class="nm-scope"><label><input type="radio" name="nm-scope" value="device" checked> only for <b>' +
                    esc(h.name || h.ip) + '</b> (' + esc(h.ip) + ')</label><label><input type="radio" name="nm-scope" value="all"> for every ' +
                    'device on the network</label></div><ul class="nm-modal-points"><li>' + (action === 'block'
                        ? 'AdGuard Home answers queries for this domain and its subdomains with a blocked reply.'
                        : 'An exception rule: the domain and its subdomains are answered even when a blocklist contains them.') +
                    '</li><li>The rule appears in AdGuard Home under Filters &gt; Custom filtering rules, where it can also be removed.</li>' +
                    '<li>A rule for one device follows its address ' + esc(h.ip) + '.</li></ul>';
            }
            var scope = 'device';
            $(document).on('change.nmscope', 'input[name=nm-scope]', function () { scope = this.value; });
            confirmDialog(action === 'remove' ? 'Remove DNS rule' : (action === 'block' ? 'Block a domain' : 'Allow a domain'), body,
                action === 'remove' ? 'Remove rule' : (action === 'block' ? 'Block' : 'Allow'), action === 'block').always(function () {
                    $(document).off('change.nmscope');
                }).done(function () {
                    search('netmap/adguard/rule', {domain: domain, action: action, scope: action === 'remove' ? scopeFixed : scope, ip: h.ip})
                        .done(function (r) {
                            if (!r || r.status !== 'ok') { fwMessage('danger', esc((r && r.message) || 'AdGuard Home refused the rule')); }
                            loadAdguard();
                        });
                });
        });

        $drawer.on('click', '[data-dns-reload]', function (e) { e.preventDefault(); loadAdguard(); renderDrawer(); });
        $drawer.on('click', '[data-dns-block]', function () {
            var h = selectedHost(), block = $(this).data('dns-block') === 1;
            confirmDialog(block ? 'Block DNS in AdGuard Home' : 'Allow DNS in AdGuard Home',
                '<p>' + (block ? 'Block' : 'Allow') + ' DNS for <b>' + esc(h.name || h.ip) + '</b> (' + esc(h.ip) + ')?</p><ul class="nm-modal-points">' +
                (block ? '<li>AdGuard Home stops answering its DNS queries, so it cannot find names on the Internet or the local network.</li>' +
                    '<li>The block is on the address ' + esc(h.ip) + ': reserve it in Kea, or the block moves to another device when the address changes.</li>' +
                    '<li>A device using another DNS server is not affected; Ban stops it at the firewall instead.</li>'
                    : '<li>The address is removed from the AdGuard Home disallowed clients.</li>') + '</ul>',
                block ? 'Block DNS' : 'Allow DNS', block).done(function () {
                    search('netmap/adguard/block/' + encodeURIComponent(h.ip) + '/' + (block ? '1' : '0'), {}).done(function (r) {
                        if (!r || r.status !== 'ok') { fwMessage('danger', esc((r && r.message) || 'AdGuard Home refused the change')); }
                        loadAdguard();
                    });
                });
        });

        // ---- traffic history (Insight / NetFlow) ---------------------------
        var histSpan = 1;

        function loadHistory() {
            var h = selectedHost();
            if (!h || !h.ip) { return; }
            var mac = selected, to = Math.floor(Date.now() / 1000), from = to - histSpan * 86400;
            var url = 'diagnostics/networkinsight/top/FlowSourceAddrDetails/' + from + '/' + to + '/';
            drawerData.hist = {loading: true};
            function top(fields, filterField) {
                return $.ajax({url: API + url + fields + '/octets/50/', data: {filter_field: filterField, filter_value: h.ip},
                    dataType: 'json', cache: false, global: false});
            }
            $.when(top('dst_addr,service_port,protocol', 'src_addr'), top('src_addr,service_port,protocol', 'dst_addr')).done(function (out, inn) {
                if (selected !== mac) { return; }
                drawerData.hist = {sent: out[0] || [], received: inn[0] || []};
                renderDrawer();
            }).fail(function (xhr) {
                if (selected === mac) { drawerData.hist = {error: xhr.status}; renderDrawer(); }
            });
        }

        function historyHtml() {
            var hs = drawerData.hist;
            if (!hs || hs.loading) { return '<p class="small text-muted">' + icon('spinner fa-pulse') + ' reading Insight...</p>'; }
            if (hs.error) { return '<p class="small text-muted">Insight is not available (HTTP ' + esc(hs.error) + '). Enable NetFlow in Reporting &gt; NetFlow.</p>'; }
            // Insight keeps the volume of a connection in both directions together: one total per remote host and port,
            // whether the device opened the connection or the remote did (the same flow can appear in both lists)
            var peers = {};
            function add(rows, remoteKey) {
                $.each(rows, function (_, r) {
                    if (!r[remoteKey]) { return; }  // Insight groups what is left over under an empty address
                    var key = r[remoteKey] + '|' + r.service_port + '|' + r.protocol;
                    var p = peers[key] || (peers[key] = {ip: r[remoteKey], port: r.service_port, proto: r.protocol, total: 0});
                    p.total = Math.max(p.total, +r.total || 0);
                });
            }
            add(hs.sent || [], 'dst_addr');
            add(hs.received || [], 'src_addr');
            var list = $.map(peers, function (p) { return p; }).sort(function (a, b) { return b.total - a.total; });
            if (!list.length) { return '<p class="small text-muted">No traffic recorded in this period.</p>'; }
            var total = 0;
            $.each(list, function (_, p) { total += p.total; });
            var max = list[0].total || 1;
            return '<p class="small"><b>' + esc(bytes(total)) + '</b> exchanged with the ' + esc(list.length) + ' busiest remote hosts and ports</p>' +
                '<ul class="nm-list nm-hist-list">' + $.map(list.slice(0, 15), function (p) {
                    var name = remoteName(p.ip);
                    return '<li><div class="nm-l1"><span class="nm-r-name">' + esc(name || p.ip) + '</span><span class="nm-r-port">' +
                        esc(portLabel(p.proto, p.port)) + '</span><span class="nm-r-rate small">' +
                        esc(bytes(p.total)) + '</span></div><div class="nm-hbar"><i style="width:' + Math.max(2, Math.round(p.total * 100 / max)) +
                        '%"></i></div>' + (name ? '<div class="nm-l2"><span>' + esc(p.ip) + '</span></div>' : '') + '</li>';
                }).join('') + '</ul>';
        }

        $drawer.on('change', '.nm-hist-span', function () { histSpan = +$(this).val() || 1; loadHistory(); renderDrawer(); });

        // ---- new devices ----------------------------------------------------
        var onlyNew = false;

        function anyApproved() {
            if (!opts.new_devices) { return false; }
            for (var mac in model.custom) { if (model.custom[mac].approved) { return true; } }
            return false;
        }

        function approve(macs) {
            return call('netmap/devices/approve', {macs: macs}).then(function () { return loadHosts(); });
        }

        function newDevices() {
            return $.grep($.map(model.hosts, function (h) { return h; }), function (h) { return h.online && !h.approved; });
        }

        function adoptBanner() {
            var fresh = newDevices();
            var $a = $root.find('.nm-adopt');
            $root.find('.nm-new-count').text(anyApproved() && fresh.length ? fresh.length : '');
            $root.find('.nm-new-btn').toggleClass('active', onlyNew);
            if (!opts.new_devices) { $a.empty(); $root.find('.nm-new-btn').hide(); return; }
            if (anyApproved() || !fresh.length) { $a.empty(); return; }
            $a.html('<div class="alert alert-info nm-adopt-box">' + icon('star') + ' <b>Know your network.</b> Approve the ' + esc(fresh.length) +
                ' devices online now: from then on, every device that joins for the first time is marked <span class="nm-new-tag">new</span> ' +
                'until you approve or ban it. <button type="button" class="btn btn-success btn-xs" data-approve-all>' + icon('check') +
                ' Approve all ' + esc(fresh.length) + '</button></div>');
        }

        $root.on('click', '.nm-new-btn', function () { onlyNew = !onlyNew; draw(); });
        $root.on('click', '[data-approve-all]', function () {
            var $b = $(this).prop('disabled', true).html(icon('spinner fa-pulse') + ' Approving...');
            approve($.map(newDevices(), function (h) { return h.mac; })).always(function () { draw(); })
                .fail(function (err) { $b.prop('disabled', false).text('Approve all'); $root.find('.nm-adopt .alert').append(' <b class="text-danger">' + esc(why(err)) + '</b>'); });
        });
        $drawer.on('click', '[data-approve]', function () {
            var h = selectedHost();
            $(this).prop('disabled', true);
            approve([h.mac]).always(function () { renderEdit(); renderDrawer(); draw(); });
        });

        // ---- restrictions overview (toolbar) -----------------------------
        function restrictionsHtml() {
            var rows = [];
            $.each(FW, function (key, def) {
                var a = model.fw.aliases[def.alias];
                $.each(a ? a.content : [], function (_, mac) {
                    var h = model.hosts[mac];
                    rows.push('<li><div class="nm-l1"><span class="nm-r-name">' + esc(h ? (h.name || h.ip) : mac) + '</span><span class="nm-r-port">' +
                        esc(mac + (h && h.ip ? ' · ' + h.ip : '')) + '</span><span class="label label-' + (key === 'banned' ? 'danger' : 'warning') + '">' +
                        esc(key === 'banned' ? 'banned' : 'no Internet') + '</span><span class="nm-r-rate"><button type="button" class="btn btn-success btn-xs" ' +
                        'data-unrestrict="' + key + '" data-mac="' + esc(mac) + '">' + icon('unlock') + ' ' + (key === 'banned' ? 'Unban' : 'Allow Internet') +
                        '</button></span></div></li>');
                });
            });
            var fwd = $.map(model.fw.forwards, function (f) {
                var h = model.byIp[f.target];
                return '<li><div class="nm-l1"><span class="nm-r-name">' + esc(String(f.proto).toUpperCase() + ' ' + f.port) + '</span><span class="nm-r-port">' +
                    icon('long-arrow-right') + ' ' + esc((h ? (h.name || f.target) : f.target) + ':' + (f.localPort || f.port)) + ' · ' + esc(f.iface) + '</span>' +
                    (f.disabled ? '<span class="label label-default">disabled</span>' : '') + '</div><div class="nm-l2"><span>' + esc(f.descr || '') + '</span></div></li>';
            });
            return '<div class="nm-restrict-cols"><div><h5>Blocked devices</h5>' + (rows.length ? '<ul class="nm-list">' + rows.join('') + '</ul>'
                : '<p class="small text-muted">No device is banned or kept off the Internet.</p>') + '</div><div><h5>Port forwards</h5>' +
                (fwd.length ? '<ul class="nm-list">' + fwd.join('') + '</ul>' : '<p class="small text-muted">None.</p>') + '</div></div>';
        }

        $root.on('click', '.nm-restrict-btn', function () {
            var $box = $root.find('.nm-restrict');
            $box.toggle();
            if ($box.is(':visible')) { $box.html(restrictionsHtml()); }
        });
        $root.on('click', '[data-unrestrict]', function () {
            var $b = $(this), key = $b.data('unrestrict'), mac = $b.data('mac');
            fwDialog(key, false, model.hosts[mac] || {name: mac}).done(function () {
                $b.prop('disabled', true).html(icon('spinner fa-pulse'));
                setMember(key, mac, false).always(function () {
                    loadFirewall().always(function () { $root.find('.nm-restrict').html(restrictionsHtml()); draw(); if (selected) { renderEdit(); } });
                });
            });
        });

        // ---- polling ----------------------------------------------------
        // the live status sits next to the page title when the theme has one, otherwise in the toolbar
        var $title = $('.page-content-head h1').first();
        if ($title.length) {
            $title.append(' <small class="nm-status nm-status-head"></small>');
            $root.find('.nm-toolbar .nm-status').remove();
        }
        function status(text) { $('.nm-status').html(text); }

        // "live · updated 4 s ago", refreshed every second
        var updatedAt = 0;
        function markUpdated() { updatedAt = Date.now(); showUpdated(); }
        function showUpdated() {
            if (!updatedAt) { return; }
            var sec = Math.max(0, Math.round((Date.now() - updatedAt) / 1000));
            var text = sec < 2 ? 'just now' : (sec < 60 ? sec + ' s ago' : Math.floor(sec / 60) + ' min ago');
            status('<span title="Last read ' + esc(new Date(updatedAt).toLocaleTimeString()) + '">' + icon('circle') + ' live &middot; updated ' +
                esc(text) + '</span>');
        }
        setInterval(showUpdated, 1000);

        function loadScans() {
            return get('netmap/scan/list').done(function (d) {
                var byMac = {};
                $.each((d && d.devices) || [], function (_, x) { byMac[x.mac] = x; });
                model.scans = byMac;
            });
        }

        function loadHosts() {
            loadScans();
            return $.when(
                get('interfaces/overview/interfaces_info'),
                search('hostdiscovery/service/search', {current: 1, rowCount: -1, searchPhrase: ''}),
                search('kea/leases4/search', {current: 1, rowCount: -1, searchPhrase: ''}).then(null, function () { return $.Deferred().resolve([{rows: []}]); }),
                get('diagnostics/interface/get_arp'),
                get('instanton/status/clients').then(null, function () { return $.Deferred().resolve([null]); }),
                get('instanton/status/topology').then(null, function () { return $.Deferred().resolve([null]); }),
                get('netmap/devices/list').then(null, function () { return $.Deferred().resolve([{devices: []}]); }),
                search('kea/dhcpv4/search_reservation').then(null, function () { return $.Deferred().resolve([{rows: []}]); }),
                search('kea/dhcpv4/search_subnet').then(null, function () { return $.Deferred().resolve([{rows: []}]); }),
                loadFirewall()
            ).done(function (ifs, disc, leases, arp, icClients, icTopo, names, res, subnets) {
                model.loadNames((names[0] || {}).devices, (res[0] || {}).rows, (subnets[0] || {}).rows);
                model.loadInterfaces((ifs[0] || {}).rows);
                var ic = icClients && icClients[0], topo = icTopo && icTopo[0];
                if (ic && ic.clients) {
                    var byMac = {};
                    $.each(ic.clients, function (_, c) { byMac[c.mac] = c; });
                    model.instanton = {clients: byMac, topology: topo && topo.nodes && topo.nodes.length > 1 ? topo.nodes : null};
                }
                model.loadHosts((disc[0] || {}).rows, (leases[0] || {}).rows, arp[0]);
                syncToolbar();
                if (selected && !editing) { renderEdit(); }
            });
        }

        function loadStates() {
            return search('diagnostics/firewall/query_states', {current: 1, rowCount: 10000, searchPhrase: ''})
                .done(function (d) { model.loadStates(d.rows); });
        }

        function loadLog() {
            return get('diagnostics/firewall/log?limit=2000').done(function (d) { model.loadLog(d); });
        }

        function loadDns() {
            return get('unbound/diagnostics/dumpcache').done(function (d) { model.loadDns(d.data || []); });
        }

        function every(name, seconds, fn) {
            function run() {
                if (document.hidden) { timers[name] = setTimeout(run, 2000); return; }
                $.when(fn()).always(function () {
                    draw();
                    markUpdated();
                    timers[name] = setTimeout(run, seconds * 1000);
                });
            }
            timers[name] = setTimeout(run, seconds * 1000);
        }

        $root.on('click', '[data-reset-filters]', function () {
            $.extend(filters, {q: '', nets: {}, link: '', type: '', group: '', active: false, offline: false, ports: false});
            onlyNew = false;
            $root.find('.nm-q').val('');
            $root.find('.nm-withports').prop('checked', false);
            $root.find('.nm-type, .nm-group').val('');
            save();
            syncToolbar();
            draw();
        });

        syncToolbar();
        $stage.html('<div class="nm-loading">' + icon('spinner fa-pulse') + '<p>Reading the firewall…</p></div>');
        status(icon('spinner fa-pulse') + ' reading the firewall...');
        get('netmap/settings/options').then(function (o) {
            $.extend(opts, o || {});
            EVERY.states = Math.max(5, +opts.refresh || EVERY.states);
            $.each(opts.hidden_networks || [], function (_, id) { if (filters.nets[id] === undefined) { filters.nets[id] = true; } });
        }, function () { return $.Deferred().resolve(); }).then(function () {
            return loadHosts();
        }).then(function () {
            return $.when(loadStates(), loadLog(), loadDns());
        }).always(function () {
            loaded = true;
            draw();
            markUpdated();
            every('states', EVERY.states, loadStates);
            every('log', EVERY.log, loadLog);
            every('hosts', EVERY.hosts, loadHosts);
            every('dns', EVERY.dns, loadDns);
        }).fail(function (xhr) {
            status('<span class="text-danger">' + icon('exclamation-triangle') + ' cannot read the firewall data (HTTP ' + esc(xhr && xhr.status) + ')</span>');
            if (!Object.keys(model.hosts).length) {
                $stage.html('<div class="nm-empty">' + icon('exclamation-triangle') + '<p>The firewall data could not be read (HTTP ' +
                    esc(xhr && xhr.status) + '). Reload the page; if it persists, check the privileges of your account.</p></div>');
            }
        });
    }

    window.Netmap = {start: start, guessType: guessType, inCidr: inCidr, portLabel: portLabel};
}(window, jQuery));
