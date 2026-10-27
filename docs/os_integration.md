# Pointing the Windows OS resolver at the local server

The local DNS server must listen on port 53 because Windows DNS settings do
not support a custom DNS port. Start it from an elevated terminal:

```powershell
$env:PYTHONPATH = "src"
python -m idns.cli server --host 127.0.0.1 --port 53
```

Apply the DNS setting explicitly from a second elevated PowerShell terminal:

```powershell
.\scripts\configure_windows_dns.ps1 -InterfaceAlias "Ethernet" -Apply
```

The script saves the previous IPv4 DNS servers to
`experiments/os_integration/windows_dns_backup.json`. Restore them when done:

```powershell
.\scripts\configure_windows_dns.ps1 -Restore
```

The script refuses to change settings without `-Apply` or `-Restore`, and it
does not run automatically as part of tests. Verify with:

```powershell
nslookup example.com 127.0.0.1
```

For development on port 5353, use `dig @127.0.0.1 -p 5353 example.com`; the
OS resolver cannot target a non-standard DNS port.

## Browsing the web through the local server (Task 9.2)

The `scripts/browse_web_test.py` script proves real web traffic works through
the local DNS server without modifying OS-level DNS settings:

```powershell
$env:PYTHONPATH = "src"
python scripts/browse_web_test.py --domain example.com --output experiments/os_integration/results.json
```

The script starts the resolver on an ephemeral loopback port, sends an
explicit UDP A-record query for the target domain, then makes a raw TLS/HTTPS
GET request to the resolved IP address with the correct `Host` header. The
output JSON records the resolved IP, the HTTP status line, and the byte count.

A fully deterministic system test (no Internet required) lives at
`tests/system/test_browse_web.py`. It spins up a local HTTP server alongside
the DNS server and validates the full pipeline: DNS resolution → HTTP GET →
correct body. Run it with:

```bash
pytest tests/system/test_browse_web.py -v
```

## Live DNS robustness validation (Task 9.3)

The opt-in `scripts/live_robustness_validation.py` check exercises the
production resolver against live root and authoritative servers. It checks A
and AAAA answers for a known domain, confirms a repeated A lookup is served
from cache, and verifies NXDOMAIN behavior using the reserved `.invalid`
namespace. It does not change OS DNS settings.

```powershell
$env:PYTHONPATH = "src"
python scripts/live_robustness_validation.py --output experiments/os_integration/robustness.json
```

Use `--domain` to select another known domain and `--negative-domain` only
with a name in `.invalid`. This makes real DNS queries and is intentionally
not part of automated unit or system test runs. The JSON report gives each
check's status, answer types, cache status, logical query count, and elapsed
time; the command exits nonzero if any expectation fails.
