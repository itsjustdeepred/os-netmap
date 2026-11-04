#!/bin/sh
#
# Remove a plugin installed with install.sh.
#
set -e
[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)/src"
(cd "${SRC}" && find . -type f) | while read -r f; do
	rm -f "/usr/local/${f#./}"
done
rmdir /usr/local/opnsense/mvc/app/controllers/OPNsense/Netmap \
	/usr/local/opnsense/mvc/app/models/OPNsense/Netmap/Menu \
	/usr/local/opnsense/mvc/app/models/OPNsense/Netmap/ACL \
	/usr/local/opnsense/mvc/app/models/OPNsense/Netmap \
	/usr/local/opnsense/mvc/app/views/OPNsense/Netmap \
	/usr/local/opnsense/www/js/netmap 2>/dev/null || true
rm -f /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
echo ">>> removed"
