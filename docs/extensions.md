# EDNS(0) and DNSSEC extensions

## EDNS(0)

`idns.extensions.edns0` provides validated helpers for EDNS configuration and
the commonly deployed NSID, COOKIE, Client Subnet, PADDING, and Extended DNS
Error options. Set `TransportConfig.edns_enabled=True` to attach an OPT record
to root, TLD, and authoritative queries. The resolver raises its receive
buffer to the negotiated EDNS payload size and preserves the DO bit and option
wire format.

## DNSSEC

`idns.extensions.dnssec` implements dependency-free RSA/SHA-1,
RSA/SHA-256, and RSA/SHA-512 DNSSEC verification. It supports DNSKEY and RRSIG
wire records, canonical DNS names/RDATA, DNSKEY key-tag calculation, signature
validity windows, and complete-message validation with
`validate_message(message)`. Unsupported algorithms are reported as
unchecked/bogus rather than accepted as secure.

```python
from idns.extensions.dnssec import validate_message

status = validate_message(message)
if status.secure:
    print("all included signatures validated")
```
