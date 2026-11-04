// Offline tests of the browser code: node tests/test_netmap.js
'use strict';
const assert = require('assert');
global.window = {};
global.jQuery = function () {};
require('../src/opnsense/www/js/netmap/netmap.js');
const N = window.Netmap;

const kinds = {
    'Shelly Lavatrice': 'plug', 'Lavatrice': 'washer', 'Asciugatrice': 'dryer', 'Lavastoviglie': 'dishwasher',
    'Frigo': 'fridge', 'Forno': 'oven', 'Huawei SmartGrid': 'solar', 'Pompa di Calore': 'climate',
    'Sonos Camera Matrimoniale': 'speaker', 'Hikvision Camera INGRESSO': 'camera', 'Citofono Hikvision (IN)': 'intercom',
    'Access Point Studio': 'ap', 'Proxmox (debian 100)': 'server', 'TV Salotto': 'tv', 'Tab-S9-FE': 'tablet',
    'Synology NAS (VLAN_1)': 'nas', 'Navimow X450': 'vacuum', 'LED Cucina': 'light', 'iPhone': 'phone'
};
for (const [name, kind] of Object.entries(kinds)) {
    assert.strictEqual(N.guessType([name], '')[0], kind, name);
}
assert.deepStrictEqual(N.guessType([''], 'Hangzhou Hikvision Digital Technology'), ['camera', 'manufacturer']);
assert.deepStrictEqual(N.guessType(['aa:bb:cc:dd:ee:ff'], ''), ['unknown', '']);

assert.ok(N.inCidr('10.0.20.5', '10.0.20.1/24'));
assert.ok(!N.inCidr('10.0.21.5', '10.0.20.1/24'));
assert.ok(N.inCidr('192.168.1.10', '192.168.0.0/16'));
assert.ok(!N.inCidr('nonsense', '10.0.0.0/8'));
console.log('netmap.js: all tests passed');
