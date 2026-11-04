#!/bin/sh
#
# Install the plugin on an OPNsense firewall without building a package.
# Run as root on the firewall from the root of this repository:
#
#   sh install.sh
#
set -e

SRC="$(cd "$(dirname "$0")" && pwd)/src"
[ -d "${SRC}/opnsense" ] || { echo "run from the plugin repository" >&2; exit 1; }
[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }


echo ">>> copying files"
(cd "${SRC}" && find . -type f) | while read -r f; do
	dst="/usr/local/${f#./}"
	mkdir -p "$(dirname "${dst}")"
	install -m 0644 "${SRC}/${f}" "${dst}"
done
chmod 0755 /usr/local/opnsense/scripts/netmap/*.py
mkdir -p /var/db/netmap/scans && chmod 0750 /var/db/netmap /var/db/netmap/scans
rm -f /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
service configd restart
command -v nmap >/dev/null 2>&1 || echo ">>> optional: pkg install nmap to enable port scans"
echo ">>> done: open Network Map > Dashboard"
