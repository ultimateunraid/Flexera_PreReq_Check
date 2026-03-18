# Flexera One Prerequisites Check

PowerShell script that validates TLS versions, .NET Framework 4.8, and network connectivity to Flexera One cloud endpoints — run on a Beacon or server before deployment.

## Language Constraints (Critical)

- **PowerShell 5.1** target — avoid PS 7-only syntax
- No null-coalescing (`??`), ternary (`?:`), or null-conditional (`?.`) operators
- Run elevated (Administrator) — required for TLS registry checks

## Architecture

Single-script design: `FlexeraOne-PreReqCheck.ps1`

No configuration block needed — the script is non-interactive and tests a hardcoded set of Flexera One endpoints.

## What It Checks

| Check | Detail |
|-------|--------|
| TLS versions | TLS 1.2 (required), TLS 1.3 (optional) |
| .NET Framework | 4.8 or compatible |
| URL connectivity | Flexera One endpoints across US, EU, APAC regions |
| CRL URLs | Auto-discovered from live SSL certs on Flexera services |

### Endpoints Tested

- `app.flexera.com`, `login.flexera.com`, `secure.flexera.com`, `api.flexera.com`
- `beacon.flexnetmanager.com`, `data.flexnetmanager.com`
- Regional variants for US / EU / APAC

### CRL Auto-Discovery

Pulls CRL URLs dynamically from live certificates on the above endpoints. Only CRLs from trusted CAs are included (`*.amazontrust.com`, `*.digicert.com`, `*.lencr.org`). Discovered CRLs are merged with the hardcoded list.

## Running

```powershell
# Elevated PowerShell 5.1
.\FlexeraOne-PreReqCheck.ps1
```

## Related Repos

- [ZFP-Test-Script](https://github.com/ultimateunraid/ZFP-Test-Script) — ZFP/ZFA agentless scan diagnostics
- [PreReq_Snow](https://github.com/ultimateunraid/PreReq_Snow) — Snow Atlas prerequisites check
