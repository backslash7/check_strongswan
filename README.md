# check_strongswan

A Nagios/NRPE plugin that monitors [strongSwan](https://www.strongswan.org/) IPsec connections
through the [vici](https://docs.strongswan.org/docs/latest/plugins/vici.html) interface. It reports
whether configured connections are up, how long until IKE and CHILD SAs rekey or expire, and how many
SAs are installed. Output includes performance data in the format described by the
[Nagios plugin development guidelines](https://nagios-plugins.org/doc/guidelines.html#performance).

The plugin is a single static binary. Apart from the vici socket it has no runtime dependencies, so
you can drop it on a host and call it from NRPE.

## Requirements

strongSwan 5.x or newer with the `vici` plugin loaded and its control socket enabled. The plugin
does not use `stroke`, so you don't need it.

## Installation

Prebuilt binaries for Linux and FreeBSD (amd64, arm64, armv6, armv7 and 386) are on the
[releases page](https://github.com/backslash7/check_strongswan/releases), along with deb and rpm
packages and a `checksums.txt` file.

The deb and rpm packages install the binary to `/usr/lib/nagios/plugins`. On FreeBSD, unpack the
tar.gz and copy the binary to the NRPE plugin directory, usually `/usr/local/libexec/nagios/`. The
strongSwan port uses the same socket path, `/var/run/charon.vici`.

With a Go toolchain you can also install from source:

```sh
go install github.com/backslash7/check_strongswan@latest
```

## Building

```sh
make build
```

This produces a static `check_strongswan` binary with CGO disabled, which you can copy to any host
with the same OS and architecture. To cross-compile a single target, set `GOARCH`, for example
`GOARCH=arm64 make build`.

To build the whole release matrix locally, use [goreleaser](https://goreleaser.com/):

```sh
make release-snapshot   # goreleaser release --snapshot --clean
```

The binaries, tar.gz archives, checksums and deb/rpm packages end up in `dist/`. Snapshot builds
don't publish anything and don't need a token.

## Releasing

Releases are built by the `release` GitHub Actions workflow (`.github/workflows/release.yml`). Pushing
a tag that starts with `v` runs the tests and then goreleaser, which uploads the archives and
packages to a GitHub release for that tag:

```sh
git tag -a v1.0.0 -m "v1.0.0"
git push origin v1.0.0
```

Tags with a pre-release suffix such as `v1.1.0-rc1` are marked as pre-releases. To release from your
own machine instead, export a `GITHUB_TOKEN` with `contents: write` access to the repository and run
`make release`.

## Checks performed

- Connection up/down. Every loaded connection (vici `list-conns`) needs at least one `ESTABLISHED`
  IKE_SA. A connection that is down is CRITICAL.
- Phase 1 (IKE_SA) lifetimes: seconds until rekey and until reauthentication, compared against the
  thresholds. If a connection has rekeying or reauthentication disabled, that check is skipped for
  it.
- Phase 2 (CHILD_SA) lifetimes: seconds until rekey and until the hard lifetime runs out. While a
  rekey overlap is in progress, the plugin uses the larger remaining time for each child.
- Installed CHILD_SA count, compared with the number of children configured for the connection.
  Missing children usually point to broken traffic selectors.
- Perfdata: uptime and rekey times per connection, lifetimes and traffic totals per child, and the
  daemon-wide counts of IKE_SAs and half-open IKE_SAs. Traffic totals are bytes and packets in and
  out of the currently installed SAs, so they reset on every rekey.

## Usage

```
check_strongswan [flags]

  -socket string        path to the charon vici socket (default "/var/run/charon.vici")
  -timeout duration     overall plugin timeout, keep below the NRPE timeout (default 10s)
  -conn value           check only this connection; repeatable or comma-separated (default: all loaded)
  -ignore value         exclude this connection; repeatable or comma-separated
  -ike-rekey-warn / -ike-rekey-crit value      thresholds for IKE_SA rekey time
  -ike-reauth-warn / -ike-reauth-crit value    thresholds for IKE_SA reauthentication time
  -child-rekey-warn / -child-rekey-crit value  thresholds for CHILD_SA rekey time
  -child-life-warn / -child-life-crit value    thresholds for CHILD_SA remaining lifetime
  -children-severity string                    severity when fewer CHILD_SAs are installed than
                                               configured: warning, critical or ok (default "critical")
  -version              print version and exit
```

### Threshold semantics

All lifetime thresholds are in seconds remaining. A bare number `N` alerts when the value drops
below `N`, the same as the Nagios range `N:`. This is the opposite of the usual Nagios reading of a
bare number, on purpose: that convention suits usage metrics, and here we are counting down a
lifetime. Anything containing `:`, `@` or `~` is parsed as a full
[Nagios range](https://nagios-plugins.org/doc/guidelines.html#THRESHOLDFORMAT) (`10:20`, `~:10`,
`@10:20` and so on).

To warn when an IKE_SA rekeys in less than 10 minutes and go critical below 5:

```sh
check_strongswan --ike-rekey-warn 600 --ike-rekey-crit 300
```

### Exit codes

The standard Nagios codes: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN. A connection that is down is
CRITICAL. A connection you asked for with `--conn` that isn't loaded is UNKNOWN, and so are vici
connection or parse failures. When results are combined, an UNKNOWN never hides a real WARNING or
CRITICAL.

### Sample output

```
STRONGSWAN CRITICAL - 1/2 connections up | 'conns_up'=1;;;0;2 'conns_down'=1;;;0;2 'office_established'=1234s;;;0 'office_ike_rekey'=9000s;600:;300:;0 'office_children'=2;;;0;2 'office_net_rekey'=2500s;;;0 'office_net_life'=3300s;;;0 'office_net_bytes_in'=1000B;;;0 'office_net_bytes_out'=2000B;;;0 'ike_sas'=1;;;0 'half_open_ike_sas'=0;;;0
CRITICAL: connection "branch" is down (no IKE_SA)
office: ESTABLISHED (IKEv2), up 1234s
```

## NRPE deployment

Copy the binary to the plugin directory on the target machine and define the command:

```
# /etc/nagios/nrpe.d/check_strongswan.cfg
command[check_strongswan]=sudo /usr/lib/nagios/plugins/check_strongswan --ike-rekey-warn 600 --child-rekey-warn 300
```

On FreeBSD, use `doas` instead of `sudo` and the port's plugin path
(`/usr/local/libexec/nagios/check_strongswan`). See [Permissions](#permissions).

Set `-timeout` lower than the NRPE `command_timeout`. That way the plugin always gets to print an
UNKNOWN that Nagios can parse, instead of being killed without output.

## Permissions

The vici control socket (usually `/var/run/charon.vici`) is readable only by root by default. NRPE
shouldn't run as root, so the recommended setup is a narrow privilege escalation rule for this one
binary, plus the matching prefix in the NRPE command definition.

### Linux (sudo)

```
# /etc/sudoers.d/check_strongswan
nrpe ALL=(root) NOPASSWD: /usr/lib/nagios/plugins/check_strongswan
```

```
# nrpe.cfg
command[check_strongswan]=sudo /usr/lib/nagios/plugins/check_strongswan
```

Replace `nrpe` with `nagios` or whichever account your NRPE daemon runs as.

### FreeBSD (doas)

FreeBSD hosts usually have `doas` (the `security/doas` port) rather than sudo:

```
# /usr/local/etc/doas.conf
permit nopass nagios as root cmd /usr/local/libexec/nagios/check_strongswan
```

```
# nrpe.cfg
command[check_strongswan]=doas /usr/local/libexec/nagios/check_strongswan
```

The `nrpe3` port runs the daemon as `nagios`; change the rule if yours is different. You need
`permit nopass` because NRPE can't answer a password prompt. Limiting the rule to a single `cmd`
means the nagios user can run this binary as root and nothing else.

Another option is to configure strongSwan to put the vici socket somewhere else with group access
(the `charon.plugins.vici.socket` option in strongswan.conf) and pass that path with `--socket`.
Don't run the NRPE daemon as root just to reach the socket.

## Testing

```sh
make test          # unit tests (no strongSwan needed)
sudo make integration  # integration test against a live charon vici socket
```

The integration test skips itself if the socket isn't there. It looks at `/var/run/charon.vici` by
default; set `CHECK_STRONGSWAN_SOCKET` to use another path.

To test an ESTABLISHED connection locally without touching real tunnels, set up a loopback pair:
two swanctl connections between `127.0.0.1` and `127.0.0.2` using a PSK. Then bring it up with
`swanctl --initiate --child <name>`.

## Roadmap

- Certificate expiry check via vici `list-certs` (`--cert-warn`/`--cert-crit` in days).
- Warning and critical thresholds on half-open IKE_SAs, which can indicate a DoS. The perfdata is
  already there.
- Trap/on-demand connections (`ROUTED` children without an IKE_SA), via `--allow-routed` or a
  per-connection `--down-ok`.
- Checking a remote host over a TCP vici socket.
- CI on pull requests (vet, test, cross-compile).

## License

MIT. See [LICENSE](LICENSE).
