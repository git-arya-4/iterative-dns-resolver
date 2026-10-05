# Local DNS Server Daemon Specification

**Owner**: Swastik + Arya + Avidipta  
**Subsystem Package**: `src/idns/server/`  
**Status**: Implemented for UDP and optional TCP listening.

The server decodes incoming DNS requests, routes them through the configured
resolver, and returns encoded responses. UDP is the default listener; pass
`--tcp` to the CLI for DNS-over-TCP two-byte length framing. Both listeners
support port `0` for ephemeral-port use and can be stopped with `close()`.
