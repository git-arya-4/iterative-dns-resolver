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
