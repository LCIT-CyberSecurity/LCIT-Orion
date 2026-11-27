# Build the native Orion probe package

The `build-probe-deb.sh` script creates an architecture-independent `.deb`
containing the probe, existing Orion TLS/SSH/IPsec engines, systemd unit and
maintainer scripts. Engine executables and Python runtime dependencies are
installed as Debian packages. It does not configure a target scope, certificate,
token or pairing secret.

Build in a disposable directory:

```sh
ops/package/build-probe-deb.sh 0.1.0 /tmp/orion-probe-packages
```

To sign a laboratory build, pass a locally provisioned GPG key ID as the third
argument. The detached armored signature is a laboratory signature, not an
official release signature:

```sh
ops/package/build-probe-deb.sh 0.1.0 /tmp/orion-probe-packages LAB_KEY_ID
gpg --verify /tmp/orion-probe-packages/orion-probe_0.1.0_all.deb.asc \
  /tmp/orion-probe-packages/orion-probe_0.1.0_all.deb
```

Install the package and provision a real HTTPS identity and one-time pairing
code through the approved local channel before enabling the service:

```sh
sudo apt install ./orion-probe_0.1.0_all.deb
sudo install -o root -g orion-probe -m 0640 \
  /etc/orion-probe/config.json.example /etc/orion-probe/config.json
sudoedit /etc/orion-probe/config.json
sudo install -o orion-probe -g orion-probe -m 0644 tls.crt /etc/orion-probe/tls.crt
sudo install -o orion-probe -g orion-probe -m 0600 tls.key /etc/orion-probe/tls.key
sudo systemctl enable --now orion-probe.service
sudo systemctl status orion-probe.service
```

Replace the example pairing hash and expiry with an expiring, random, one-time
code hash and timestamp. The example is intentionally not a runnable credential
configuration. Preserve `/var/lib/orion-probe` during package removal or
upgrade; maintainer scripts never delete it.

The package can be structurally built and inspected with `dpkg-deb`. A real
install/start validation must be run on a clean Debian 13 host; a successful
package build on another distribution is not that validation.
