# Email Runbooks

Investigation runbooks for email-based alerts from Microsoft Defender for Office 365, Exchange Online, and Sentinel Analytics.

{% set cat_runbooks = categories['email'].runbooks %}
{% if cat_runbooks %}
## Published Runbooks

| ID | Alert Name | Severity | Key Log Sources |
|----|-----------|----------|-----------------|
{% for rb in cat_runbooks %}
| {{ rb.id }} | [{{ rb.title }}]({{ rb.file_stem }}.md) | {{ rb.severity | capitalize }} | {{ rb.key_log_sources | join(', ') }} |
{% endfor %}

{% endif %}
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

- **OfficeActivity** - Exchange Online operations including inbox rule creation (M365 E3+)
- **EmailEvents** - Email message flow with delivery verdict (MDO P2)
- **EmailUrlInfo** - URLs extracted from emails (MDO P2)
- **EmailAttachmentInfo** - Attachment metadata and hashes (MDO P2)
- **EmailPostDeliveryEvents** - ZAP and post-delivery actions (MDO P2)
- **UrlClickEvents** - SafeLinks click tracking (MDO P2)
- **CloudAppEvents** - Defender for Cloud Apps detections (M365 E5)

See [Log Sources Reference](../../log-sources.md) for full details.
