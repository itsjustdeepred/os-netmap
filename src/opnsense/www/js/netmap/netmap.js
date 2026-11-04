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
        voip: ['VoIP phone', 'phone'], iot: ['Smart home', 'lightbulb-o'], climate: ['Climate / heating', 'thermometer-half'],
        appliance: ['Appliance', 'cutlery'], ev: ['EV charger', 'car'], power: ['UPS / power', 'battery-full'],
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
        ['iot', /shelly|sonoff|tasmota|esphome|\besp(32|8266)?\b|tuya|\bkasa\b|tapo p\d+|smart ?plug/],
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
        ['climate', /air ?condition|climat|condizionat|thermostat|termostato|heat ?pump|pompa di calore|caldaia|boiler|daikin|tado|netatmo|\bhvac\b/],
        ['appliance', /fridge|frigo|refrigerator|lavatrice|washer|washing|dryer|asciugatrice|dishwasher|lavastoviglie|oven|forno|cooktop|induction|piano cottura|\bhood\b|cappa|microwave|coffee|caffe|miele|\bneff\b|bosch|siemens|robot|roborock|roomba|vacuum|aspirapolvere|purifier/],
        ['power', /\bups\b|\bpdu\b|inverter|solar|fotovoltaico/],
        ['iot', /sensor|sensore|presence|motion|\bplug\b|presa|relay|rele|zigbee|z-?wave|gateway|bridge|\bhue\b|\bled\b|lamp|lampada|\bluce\b|light|weather|meteo|domotic|smart|vimar|bticino|irrigat|garage|gate|cancello/],
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
        ['iot', /espressif|shelly|allterco|tuya|lumi united|aqara|itead|signify|philips lighting|lifx|nanoleaf|ecobee|netatmo|weatherflow|laird|vimar|bticino|legrand|silicon labs|nordic semiconductor|texas instruments|murata|azurewave|seongji|sji industry|chongqing fugui|meross|wiz connected|wistron neweb|universal global scientific|hui zhou gaoshengda/i],
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
    // without switch and access point data the connection is a guess from the kind of device
    var WIFI_KINDS = {phone: 1, tablet: 1, watch: 1, laptop: 1, iot: 1, appliance: 1, climate: 1, speaker: 1, media: 1, ev: 1};
    var LAN_KINDS = {camera: 1, nvr: 1, nas: 1, server: 1, vm: 1, computer: 1, 'switch': 1, ap: 1, network: 1, router: 1,
        firewall: 1, alarm: 1, intercom: 1, power: 1, voip: 1, console: 1};

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
        this.updated = {};
    }

    Model.prototype.netOf = function (ip) {
        for (var i = 0; i < this.nets.length; i++) {
            if (inCidr(ip, this.nets[i].cidr)) { return this.nets[i]; }
        }
        return null;
    };

    Model.prototype.loadInterfaces = function (rows) {
        var nets = [], own = {}, wanNets = [];
        $.each(rows || [], function (_, r) {
            if (!r.identifier || !r.addr4 || r.identifier === 'lo0') { return; }
            $.each(r.ipv4 || [], function (_, a) { own[String(a.ipaddr || a.address || '').split('/')[0]] = 1; });
            own[String(r.addr4).split('/')[0]] = 1;
            var bits = +String(r.addr4).split('/')[1];
            // an IPv4 gateway marks the uplink (an IPv6 router advertisement on a LAN does not)
            var wan = (r.gateways || []).some(function (g) { return String(g).indexOf(':') < 0; }) || /^wan\b/i.test(r.description || '');
            if (wan) {
                $.each(r.ipv4 || [{ipaddr: r.addr4}], function (_, a) { wanNets.push(a.ipaddr || a.address); });
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
            h.name = (ic && (ic.description || ic.hostname || ic.port_label || ic.cloud_name)) || (h.lease && h.lease.hostname) ||
                h.arpName || '';
            var kind = ic && ic.type && ic.type !== 'unknown' ? [ic.type, 'Instant On'] : guessType([h.name], h.vendor);
            h.type = TYPES[kind[0]] ? kind[0] : 'unknown';
            h.typeSource = kind[1];
            // how it is connected: known from Instant On, otherwise a guess
            if (ic && ic.connection) {
                h.link = ic.connection === 'wireless' ? 'wifi' : 'lan';
                h.linkKnown = true;
            } else {
                h.link = h.random || WIFI_KINDS[h.type] ? 'wifi' : (LAN_KINDS[h.type] ? 'lan' : '');
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

        $root.html(
            '<div class="nm-toolbar">' +
            '  <div class="btn-group nm-view" role="group">' +
            '    <button type="button" class="btn btn-default btn-sm" data-view="networks">' + icon('th-large') + ' Networks</button>' +
            '    <button type="button" class="btn btn-default btn-sm" data-view="physical">' + icon('sitemap') + ' Physical</button>' +
            '  </div>' +
            '  <input type="search" class="form-control input-sm nm-q" placeholder="Find name, IP, MAC or maker">' +
            '  <div class="btn-group nm-link" role="group">' +
            '    <button type="button" class="btn btn-default btn-sm" data-link="">All</button>' +
            '    <button type="button" class="btn btn-default btn-sm" data-link="lan"><span class="nm-lan-tag">LAN</span> Cable</button>' +
            '    <button type="button" class="btn btn-default btn-sm" data-link="wifi">' + icon('wifi') + ' Wi-Fi</button>' +
            '    <button type="button" class="btn btn-default btn-sm" data-link="none" title="Connection not known">?</button>' +
            '  </div>' +
            '  <select class="form-control input-sm nm-type"><option value="">every kind</option></select>' +
            '  <label class="nm-check"><input type="checkbox" class="nm-active"> talking now</label>' +
            '  <label class="nm-check"><input type="checkbox" class="nm-offline"> offline too</label>' +
            '  <select class="form-control input-sm nm-sort"><option value="traffic">by traffic</option><option value="name">by name</option>' +
            '    <option value="ip">by address</option></select>' +
            '  <span class="nm-status text-muted"></span>' +
            '</div>' +
            '<div class="nm-chips"></div>' +
            '<div class="nm-guess-note small text-muted"></div>' +
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
            $root.find('[data-view=physical]').prop('disabled', !(model.instanton && model.instanton.topology))
                .attr('title', model.instanton && model.instanton.topology ? 'Switches and access points (Instant On plugin)'
                    : 'Needs the Instant On plugin to know the switches and access points');
        }

        $root.on('click', '[data-view]', function () { filters.view = $(this).data('view'); save(); syncToolbar(); draw(); });
        $root.on('click', '[data-link]', function () { filters.link = $(this).data('link'); save(); syncToolbar(); draw(); });
        $root.on('input', '.nm-q', function () { filters.q = $(this).val().toLowerCase(); draw(); });
        $root.on('change', '.nm-type', function () { filters.type = $(this).val(); draw(); });
        $root.on('change', '.nm-active', function () { filters.active = this.checked; save(); draw(); });
        $root.on('change', '.nm-offline', function () { filters.offline = this.checked; save(); draw(); });
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
            if (filters.active && !(st.traffic.up + st.traffic.down > 0)) { return false; }
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
            return '<span class="nm-link nm-unknown" title="Connection not known">' + icon('question') + '</span>';
        }

        function card(h, st) {
            var t = st.traffic, live = t.up + t.down;
            var level = live > 5e6 ? 4 : live > 5e5 ? 3 : live > 2e4 ? 2 : live > 0 ? 1 : 0;
            return '<div class="nm-card nm-act-' + level + (h.online ? '' : ' nm-off') + (selected === h.mac ? ' nm-sel' : '') +
                '" data-mac="' + esc(h.mac) + '" tabindex="0" role="button" style="--net:' + (h.net ? h.net.color : '#999') + '">' +
                '<span class="nm-ico" title="' + esc(TYPES[h.type][0] + (h.typeSource ? ' (from ' + h.typeSource + ')' : '')) + '">' +
                icon(TYPES[h.type][1]) + '</span>' +
                '<span class="nm-body"><span class="nm-name">' + esc(h.name || h.ip || h.mac) + '</span>' +
                '<span class="nm-sub">' + esc(h.name ? h.ip : (h.random ? 'private MAC' : h.vendor || h.mac)) + '</span>' +
                '<span class="nm-rate">' + (live > 0 ? icon('arrow-down') + esc(rate(t.down)) + ' ' + icon('arrow-up') + esc(rate(t.up))
                    : (t.conns ? esc(t.conns) + ' conn.' : (h.online ? 'idle' : 'offline ' + esc(ago(h.lastSeen))))) + '</span></span>' +
                '<span class="nm-side">' + linkBadge(h) +
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

        function fillTypes() {
            var seen = {};
            $.each(model.hosts, function (_, h) { seen[h.type] = 1; });
            var html = '<option value="">every kind</option>' + $.map(Object.keys(seen).sort(function (a, b) {
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
        function drawPhysical(items) {
            var nodes = model.instanton.topology, kids = {}, root = null, shown = {};
            $.each(items, function (_, it) { shown[it.h.mac] = it; });
            $.each(nodes, function (_, n) {
                if (!n.parent) { root = n; } else { (kids[n.parent] = kids[n.parent] || []).push(n); }
            });
            var placed = {};
            function infraCard(n) {
                var l = n.link || {};
                var cls = n.type === 'switch' ? 'nm-sw' : n.type === 'ap' ? 'nm-ap' : 'nm-fwc';
                var ico = n.type === 'switch' ? 'sitemap' : n.type === 'ap' ? 'wifi' : 'shield';
                return '<div class="nm-infra ' + cls + (n.online === false ? ' nm-off' : '') + '">' + icon(ico) +
                    '<div><b>' + esc(n.label) + '</b><small>' + esc(n.sub || '') + '</small></div>' +
                    (l.text || l.speed ? '<span class="nm-port" title="Link towards the firewall">' + esc([l.text, l.speed, l.poe_w ? l.poe_w + ' W' : '',
                        l.snr !== undefined && l.snr !== null ? l.snr + ' dB' : ''].filter(Boolean).join(' · ')) + '</span>' : '') + '</div>';
            }
            function branch(n) {
                var children = kids[n.id] || [];
                var infra = children.filter(function (c) { return !c.client; });
                var leaves = [];
                $.each(children, function (_, c) {
                    if (c.client && shown[c.mac]) { leaves.push(shown[c.mac]); placed[c.mac] = 1; }
                });
                leaves.sort(sorter);
                var kind = (n.link || {}).kind || 'wired';
                var html = '<li class="nm-li nm-k-' + esc(kind) + '">' + infraCard(n);
                if (infra.length || leaves.length) {
                    html += '<ul>';
                    if (leaves.length) {
                        html += '<li class="nm-li nm-leaves nm-k-' + (n.type === 'ap' ? 'wireless' : 'wired') + '"><div class="nm-grid">' +
                            $.map(leaves, function (it) { return card(it.h, it.st); }).join('') + '</div></li>';
                    }
                    $.each(infra, function (_, c) { html += branch(c); });
                    html += '</ul>';
                }
                return html + '</li>';
            }
            if (!root) { $stage.html('<p class="text-muted">No topology.</p>'); return; }
            var tree = '<div class="nm-tree"><ul>' + branch(root) + '</ul></div>';
            var rest = items.filter(function (it) { return !placed[it.h.mac]; });
            rest.sort(sorter);
            $stage.html(tree + (rest.length ? '<section class="nm-net nm-elsewhere"><header><b>Not on a monitored switch or access point</b>' +
                '<span class="text-muted">VPN, other switches, or seen only by the firewall</span></header><div class="nm-grid">' +
                $.map(rest, function (it) { return card(it.h, it.st); }).join('') + '</div></section>' : ''));
        }

        function draw() {
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
            var exact = model.instanton && model.instanton.clients;
            $root.find('.nm-guess-note').html(exact ? '' : icon('info-circle') + ' Cable or Wi-Fi is <b>guessed</b> from the kind of ' +
                'device (faded icons): the firewall cannot see how a device reaches the switch. With the Instant On plugin installed the ' +
                'map reads it from the switches and access points.');
            if (filters.view === 'physical' && model.instanton && model.instanton.topology) {
                drawPhysical(items);
            } else {
                drawNetworks(items);
            }
            if (selected) { renderDrawer(); }
        }

        // ---- device drawer ---------------------------------------------
        var drawerData = {rows: [], prev: {}, history: [], log: [], scan: null};

        function openDrawer(mac) {
            selected = mac;
            drawerData = {rows: [], prev: {}, history: [], log: [], scan: null};
            $drawer.addClass('nm-open').attr('aria-hidden', 'false');
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
        $(document).on('keydown', function (e) { if (e.key === 'Escape' && selected) { closeDrawer(); } });

        // ---- port scan (nmap on the firewall) ----------------------------
        function loadScan() {
            clearTimeout(timers.scan);
            var h = model.hosts[selected];
            if (!h || !h.ip) { return; }
            var mac = selected;
            get('netmap/scan/status/' + encodeURIComponent(h.ip)).done(function (d) {
                if (selected !== mac) { return; }
                drawerData.scan = d;
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
            search('netmap/scan/start/' + encodeURIComponent(h.ip) + '/' + profile, {}).done(function (d) {
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

        function scanHtml(h) {
            var sc = drawerData.scan;
            var buttons = '<div class="nm-scan-tools"><button type="button" class="btn btn-default btn-xs" data-scan="quick" ' +
                'title="The 200 most common ports with service names, about a minute">' + icon('search') + ' Quick scan</button> ' +
                '<button type="button" class="btn btn-default btn-xs" data-scan="full" title="Every TCP port, service versions and ' +
                'operating system, several minutes">' + icon('crosshairs') + ' Full scan</button></div>';
            var note = '<p class="small text-muted">nmap runs on the firewall and only scans devices on its own networks. Some ' +
                'cheap IoT devices dislike full scans; a quick scan is gentle.</p>';
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
                var prev = {};
                $.each(((sc.previous || {}).ports) || [], function (_, p) { prev[p.proto + p.port] = 1; });
                var hasPrev = !!(sc.previous && sc.previous.ports);
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
            return model.dns[ip] || '';
        }

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
                ['Kind', esc(TYPES[h.type][0]) + (h.typeSource ? ' <span class="text-muted small">from ' + esc(h.typeSource) + '</span>' : '')],
                ['Connection', h.link ? linkBadge(h) + ' ' + esc(h.link === 'wifi' ? 'Wi-Fi' : 'cable') + (h.linkKnown ? '' : ' <span class="text-muted small">(guess)</span>') +
                    (ic.ap ? ' via <b>' + esc(ic.ap) + '</b>' : '') + (ic.ssid ? ' "' + esc(ic.ssid) + '"' : '') +
                    (ic.port ? ' port <b>' + esc((ic.switch_name ? ic.switch_name + ' ' : '') + ic.port) + '</b>' : '') : ''],
                ['DHCP', h.lease ? esc(h.lease.reserved ? 'reserved' : 'dynamic') + (h.lease.hostname ? ' as ' + esc(h.lease.hostname) : '') : ''],
                ['Seen', esc(h.online ? 'online now' : 'last ' + ago(h.lastSeen)) + (h.firstSeen ? ' <span class="text-muted">first ' + esc(ago(h.firstSeen)) + '</span>' : '')],
                ['Since the connections opened', icon('arrow-down') + ' ' + esc(bytes(st.traffic.received)) + ' &nbsp;' + icon('arrow-up') + ' ' +
                    esc(bytes(st.traffic.sent)) + ' <span class="text-muted">in ' + esc(st.traffic.conns) + ' connections</span>']
            ];
            var conns = drawerData.rows;
            function remoteHtml(ip, port, proto) {
                var name = remoteName(ip);
                return '<span class="nm-r-name">' + esc(name || ip) + '</span><span class="nm-r-port">' + esc(String(proto || '').toUpperCase() +
                    (port ? ' ' + port : '')) + '</span>';
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
            $drawer.html('<div class="nm-dhead"><span class="nm-ico">' + icon(TYPES[h.type][1]) + '</span><div><h4>' + esc(h.name || h.ip || h.mac) +
                '</h4><small class="text-muted">' + esc(TYPES[h.type][0]) + (h.ip ? ' &middot; ' + esc(h.ip) : '') + '</small></div>' +
                '<button type="button" class="close nm-close" aria-label="Close">&times;</button></div><div class="nm-dbody">' +
                '<h5>Live traffic through the firewall</h5>' + chart() +
                '<table class="table table-condensed nm-facts"><tbody>' + $.map(facts, function (f) {
                    return f[1] ? '<tr><th>' + esc(f[0]) + '</th><td>' + f[1] + '</td></tr>' : '';
                }).join('') + '</tbody></table>' +
                '<h5>Open ports</h5><div class="nm-scan">' + scanHtml(h) + '</div>' +
                '<h5>Connections <span class="badge">' + esc(conns.length) + '</span></h5>' + connHtml +
                '<h5>Blocked by the firewall <span class="badge">' + esc(blk.length) + '</span>' + (h.ip ? ' <a class="small" href="' +
                    esc(logLink('__addr__', h.ip)) + '" target="_blank">' + icon('external-link') + ' live log</a>' : '') + '</h5>' + blkHtml +
                '<p class="small"><a href="' + esc(logLink('__addr__', h.ip)) + '" target="_blank">' + icon('external-link') +
                ' Live firewall log of ' + esc(h.ip) + '</a> &nbsp; ' +
                '<a href="/ui/diagnostics/networkinsight" target="_blank">' + icon('external-link') + ' Insight history</a></p></div>');
        }

        // ---- polling ----------------------------------------------------
        function status(text) { $root.find('.nm-status').html(text); }

        function loadHosts() {
            return $.when(
                get('interfaces/overview/interfaces_info'),
                search('hostdiscovery/service/search', {current: 1, rowCount: -1, searchPhrase: ''}),
                search('kea/leases4/search', {current: 1, rowCount: -1, searchPhrase: ''}).then(null, function () { return $.Deferred().resolve([{rows: []}]); }),
                get('diagnostics/interface/get_arp'),
                get('instanton/status/clients').then(null, function () { return $.Deferred().resolve([null]); }),
                get('instanton/status/topology').then(null, function () { return $.Deferred().resolve([null]); })
            ).done(function (ifs, disc, leases, arp, icClients, icTopo) {
                model.loadInterfaces((ifs[0] || {}).rows);
                var ic = icClients && icClients[0], topo = icTopo && icTopo[0];
                if (ic && ic.clients) {
                    var byMac = {};
                    $.each(ic.clients, function (_, c) { byMac[c.mac] = c; });
                    model.instanton = {clients: byMac, topology: topo && topo.nodes && topo.nodes.length > 1 ? topo.nodes : null};
                }
                model.loadHosts((disc[0] || {}).rows, (leases[0] || {}).rows, arp[0]);
                syncToolbar();
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
                    status(icon('circle', 'live') + ' live, ' + new Date().toLocaleTimeString());
                    timers[name] = setTimeout(run, seconds * 1000);
                });
            }
            timers[name] = setTimeout(run, seconds * 1000);
        }

        syncToolbar();
        status(icon('spinner fa-pulse') + ' reading the firewall...');
        loadHosts().then(function () {
            return $.when(loadStates(), loadLog(), loadDns());
        }).always(function () {
            draw();
            status(icon('circle', 'live') + ' live, ' + new Date().toLocaleTimeString());
            every('states', EVERY.states, loadStates);
            every('log', EVERY.log, loadLog);
            every('hosts', EVERY.hosts, loadHosts);
            every('dns', EVERY.dns, loadDns);
        }).fail(function (xhr) {
            status('<span class="text-danger">' + icon('exclamation-triangle') + ' cannot read the firewall data (HTTP ' + esc(xhr && xhr.status) + ')</span>');
        });
    }

    window.Netmap = {start: start, guessType: guessType, inCidr: inCidr};
}(window, jQuery));
