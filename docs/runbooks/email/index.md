# Email Runbooks

Investigation runbooks for email-based alerts from Microsoft Defender for Office 365.

!!! info "Coming Soon"
    Email runbooks are planned for Tier 2 development. Check back for updates.

## Planned Runbooks

| Alert Name | Source Product | Priority |
|-----------|---------------|----------|
| Phishing email delivered | Defender for Office 365 | Tier 2 |
| Business email compromise (BEC) | Defender for Office 365 | Tier 2 |
| Malware attachment detected | Defender for Office 365 | Tier 2 |
| User clicked phishing URL | Defender for Office 365 | Tier 2 |
| ZAP (Zero-hour Auto Purge) failure | Defender for Office 365 | Tier 2 |
| Mass email to external recipients | Sentinel Analytics | Tier 2 |

## Key Log Sources

- **EmailEvents** - Email message flow with delivery verdict (MDO P2)
- **EmailUrlInfo** - URLs extracted from emails (MDO P2)
- **EmailAttachmentInfo** - Attachment metadata and hashes (MDO P2)
- **EmailPostDeliveryEvents** - ZAP and post-delivery actions (MDO P2)
- **UrlClickEvents** - SafeLinks click tracking (MDO P2)

See [Log Sources Reference](../../log-sources.md) for full details.
