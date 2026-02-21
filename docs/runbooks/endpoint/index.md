# Endpoint Runbooks

Investigation runbooks for endpoint-based alerts from Microsoft Defender for Endpoint.

!!! info "Coming Soon"
    Endpoint runbooks are planned for Tier 2 development. Check back for updates.

## Planned Runbooks

| Alert Name | Source Product | Priority |
|-----------|---------------|----------|
| Suspicious PowerShell command line | Defender for Endpoint | Tier 2 |
| Ransomware activity detected | Defender for Endpoint | Tier 2 |
| Suspicious credential dumping (LSASS) | Defender for Endpoint | Tier 2 |
| Cobalt Strike beacon activity | Defender for Endpoint | Tier 2 |
| Living-off-the-land binary (LOLBin) execution | Defender for Endpoint | Tier 2 |
| Suspicious DLL sideloading | Defender for Endpoint | Tier 2 |
| Persistence via scheduled task | Defender for Endpoint | Tier 2 |
| Suspicious registry modification | Defender for Endpoint | Tier 2 |

## Key Log Sources

- **DeviceProcessEvents** - Process creation and execution (MDE P2)
- **DeviceNetworkEvents** - Outbound network connections (MDE P2)
- **DeviceFileEvents** - File system activity (MDE P2)
- **DeviceLogonEvents** - Endpoint logon events (MDE P2)
- **DeviceRegistryEvents** - Registry modifications (MDE P2)
- **DeviceImageLoadEvents** - DLL loading events (MDE P2)
- **AlertInfo** / **AlertEvidence** - Defender XDR alert correlation (MDE P2)

See [Log Sources Reference](../../log-sources.md) for full details.
