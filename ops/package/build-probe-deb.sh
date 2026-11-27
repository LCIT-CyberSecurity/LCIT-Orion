#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 VERSION OUTPUT_DIR [GPG_KEY_ID]" >&2
    exit 2
fi

version=$1
output_dir=$2
signing_key=${3:-}
case "$version" in
    ''|*[!0-9A-Za-z.+:~_-]*) echo "invalid Debian package version" >&2; exit 2 ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output_dir=$(mkdir -p "$output_dir" && CDPATH= cd -- "$output_dir" && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/orion-probe-deb.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
package_root="$work_dir/package"
install -d "$package_root/DEBIAN" "$package_root/usr/lib/orion-probe"
install -d "$package_root/etc/orion-probe"
install -d "$package_root/usr/lib/orion-probe/remote_probe"
install -d "$package_root/usr/lib/orion-probe/tls_scanner"
install -d "$package_root/usr/lib/orion-probe/orion_app/services"
install -d "$package_root/lib/systemd/system"

cp "$repo_root"/remote_probe/*.py "$package_root/usr/lib/orion-probe/remote_probe/"
cp -R "$repo_root/tls_scanner/." "$package_root/usr/lib/orion-probe/tls_scanner/"
install -m 0644 "$repo_root/backend/src/orion_app/__init__.py" \
    "$package_root/usr/lib/orion-probe/orion_app/__init__.py"
install -m 0644 "$repo_root/backend/src/orion_app/services/__init__.py" \
    "$package_root/usr/lib/orion-probe/orion_app/services/__init__.py"
install -m 0644 "$repo_root/backend/src/orion_app/services/ssh_audit.py" \
    "$package_root/usr/lib/orion-probe/orion_app/services/ssh_audit.py"
install -m 0644 "$repo_root/backend/src/orion_app/services/ipsec.py" \
    "$package_root/usr/lib/orion-probe/orion_app/services/ipsec.py"
find "$package_root/usr/lib/orion-probe" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$package_root/usr/lib/orion-probe" -type d -exec chmod 0755 {} +
find "$package_root/usr/lib/orion-probe" -type f -exec chmod 0644 {} +
install -m 0644 "$repo_root/ops/systemd/orion-probe.service" \
    "$package_root/lib/systemd/system/orion-probe.service"
install -d "$package_root/usr/bin"
install -m 0640 "$repo_root/ops/package/config.json.example" \
    "$package_root/etc/orion-probe/config.json.example"
cat >"$package_root/usr/bin/orion-probe" <<'EOF'
#!/bin/sh
export PYTHONPATH="/usr/lib/orion-probe${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/python3 -m remote_probe.cli "$@"
EOF
chmod 0755 "$package_root/usr/bin/orion-probe"

sed "s/@VERSION@/$version/g" "$repo_root/ops/package/control.in" \
    >"$package_root/DEBIAN/control"
install -m 0755 "$repo_root/ops/package/postinst" "$package_root/DEBIAN/postinst"
install -m 0755 "$repo_root/ops/package/prerm" "$package_root/DEBIAN/prerm"
install -m 0644 "$repo_root/ops/package/conffiles" "$package_root/DEBIAN/conffiles"

deb="$output_dir/orion-probe_${version}_all.deb"
dpkg-deb --build --root-owner-group "$package_root" "$deb"
if [ -n "$signing_key" ]; then
    gpg --batch --yes --local-user "$signing_key" --armor --detach-sign --output "$deb.asc" "$deb"
fi
printf '%s\n' "$deb"
