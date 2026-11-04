#!/bin/sh
#
# Build the plugin package and a pkg(8) repository for one FreeBSD major
# version. Runs on FreeBSD or OPNsense with pkg(8):
#
#   sh packaging/build.sh <freebsd major> <output directory>
#
# The plugin is PHP, Python and templates only, so the same files work on
# every architecture; the package is marked FreeBSD:<major>:* accordingly.
#
set -eu

MAJOR=${1:?FreeBSD major version, for example 15}
OUT=${2:?output directory}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
var() { sed -n "s/^$1=[[:space:]]*//p" "${ROOT}/Makefile"; }

NAME="os-$(var PLUGIN_NAME)"
VERSION=$(var PLUGIN_VERSION)
COMMENT=$(var PLUGIN_COMMENT)
MAINTAINER=$(var PLUGIN_MAINTAINER)
WWW=$(var PLUGIN_WWW)
DEPENDS=$(var PLUGIN_DEPENDS)

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
STAGE="${WORK}/stage"
mkdir -p "${STAGE}/usr/local" "${OUT}"
(cd "${ROOT}/src" && tar cf - .) | (cd "${STAGE}/usr/local" && tar xf -)
find "${STAGE}" -name '__pycache__' -prune -exec rm -rf {} +

# file modes as installed: scripts and rc.d files executable, everything else read-only
find "${STAGE}" -type f -exec chmod 0644 {} +
find "${STAGE}" -type d -exec chmod 0755 {} +
for f in $(find "${STAGE}/usr/local/opnsense/scripts" "${STAGE}/usr/local/etc/rc.d" -type f \( -name '*.py' -o -path '*/rc.d/*' \) 2>/dev/null); do
	chmod 0755 "${f}"
done

# version file read by System > Firmware > Plugins
mkdir -p "${STAGE}/usr/local/opnsense/version"
printf '{\n  "product_id": "%s",\n  "product_name": "%s",\n  "product_version": "%s",\n  "product_website": "%s"\n}\n' \
	"${NAME}" "${NAME}" "${VERSION}" "${WWW}" > "${STAGE}/usr/local/opnsense/version/$(var PLUGIN_NAME)"

(cd "${STAGE}" && find . -type f | sed 's|^\./|/|' | sort) > "${WORK}/plist"

deps=""
for d in ${DEPENDS}; do
	origin=$(pkg rquery '%o' "${d}" 2>/dev/null || true)
	ver=$(pkg rquery '%v' "${d}" 2>/dev/null || true)
	[ -n "${origin}" ] && deps="${deps}\"${d}\" = { origin = \"${origin}\"; version = \"${ver}\"; }, "
done

# UCL manifest; here-documents keep the description and scripts verbatim
{
	printf 'name = "%s";\nversion = "%s";\norigin = "opnsense/%s";\n' "${NAME}" "${VERSION}" "${NAME}"
	printf 'comment = "%s";\nmaintainer = "%s";\nwww = "%s";\n' "${COMMENT}" "${MAINTAINER}" "${WWW}"
	printf 'abi = "FreeBSD:%s:*";\narch = "freebsd:%s:*";\nprefix = "/usr/local";\n' "${MAJOR}" "${MAJOR}"
	printf 'licenselogic = "single";\nlicenses = ["BSD2CLAUSE"];\ncategories = ["opnsense"];\n'
	printf 'deps = { %s };\n' "${deps%, }"
	printf 'desc = <<EOD\n%s\nEOD\n' "$(cat "${ROOT}/pkg-descr")"
	printf 'scripts = {\n'
	for s in post-install pre-deinstall post-deinstall; do
		printf '  %s = <<EOD\n%s\nEOD\n' "${s}" "$(cat "${ROOT}/packaging/${s}")"
	done
	printf '}\n'
} > "${WORK}/+MANIFEST"

pkg create -M "${WORK}/+MANIFEST" -r "${STAGE}" -p "${WORK}/plist" -o "${OUT}"
pkg repo "${OUT}"
ls -l "${OUT}"
