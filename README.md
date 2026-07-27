# WP2Shell Wazuh Detection Rules
---
*© NAuliajati - TangerangKota-CSIRT*

> **CVE-2026-63030** (REST batch route confusion) + **CVE-2026-60137** (WP_Query author__not_in SQLi)
> Patched in WordPress 7.0.2 / 6.9.5 / 6.8.6 (2026-07-17)

Wazuh detection rules, decoders, and documentation for identifying and responding to WP2Shell exploitation across all six operational modes - from initial reconnaissance through post-exploitation webshell access.

## Files

| File | Description |
|------|-------------|
| `wp2shell_rules.xml` | Core detection rules (IDs 625100-625399) |
| `wp2shell_decoders.xml` | Log parsing decoders (UA, URI, QS extraction) |
| `setup.sh` | One-command deployment script |

## Quick Deploy

```bash
sudo bash setup.sh
```

## Attack Detection Coverage

| Mode | Attack Phase | Auth Required | Rules |
|------|-------------|---------------|-------|
| SCAN | Reconnaissance | No | R625101–R625103, R625301 |
| CHECK | Blind SQLi Confirmation | No | R625110–R625113, R625302 |
| RCE | Pre-Auth Remote Code Execution | No | R625120–R625122, R625303 |
| SHELL | Authenticated RCE + Webshell | Yes | R625130–R625133, R625304 |
| REST WS | Pre-Auth REST API Webshell | No | R625140, R625305 |
| ROOT | Local Privilege Escalation | Yes | R625150 |
| POST-EXPLOIT | File/Account IoCs | N/A | R625201–R625211 |
| CAMPAIGN | Multi-phase correlation | N/A | R625399 |

## Rule Hierarchy

```
625100 (L0)  Group: WP2Shell attack detection (decoder-scoped)
  ├── L7    UA: wp2shell-(poc|rce)/
  ├── L7    URI: batch/v1 route
  ├── L10   BODY: nested batch JSON (route confusion)
  ├── L12   BODY: author_exclude SQLi keywords
  ├── L12   BODY: SLEEP() blind SQLi
  ├── L13   BODY: [embed] oEmbed cache poisoning
  ├── L14   URI: wp2shell plugin upload
  ├── L14   QS: tok=/rm= webshell params
  ├── L14   URI: /wp2shell/v1/ REST route
  ├── L15   CHAIN: full pre-auth RCE
  └── L15   CHAIN: active webshell access

625200 (L0)  Group: Post-exploitation IoC (FIM-scoped)
  ├── L15   FIM: webshell PHP file creation
  ├── L15   FIM: plugin dir -<6hex>
  ├── L15   FIM: $_GET['c'] + exec sink
  ├── L14   LOG: backdoor admin username
  └── L14   LOG: backdoor admin email domain

625300 (L0)  Group: High-confidence chained rules
  ├── L12   UA + batch URI (scan confirmed)
  ├── L14   batch + nested + author_exclude (SQLi confirmed)
  ├── L15   batch + nested + SLEEP (PRE-AUTH RCE)
  ├── L15   UA + tok= (WEBSHELL ACCESS)
  ├── L15   wp2shell/v1 route (REST WEBSHELL)
  └── L15   FULL CHAIN all indicators

625399 (L15) CAMPAIGN: 3+ rules in 5min from single IP
```

## References
- [CVE-2026-63030](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q)
- [CVE-2026-60137](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf)
