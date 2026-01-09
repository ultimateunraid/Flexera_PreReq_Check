# Flexera_PreReq_Check
PowerShell script to test prerequisites for Beacon connectivity.

## Features

- **TLS Version Check**: Validates that required TLS versions (1.2 and optionally 1.3) are available
- **.NET Framework Check**: Verifies .NET Framework 4.8 or compatible version is installed
- **URL Connectivity Testing**: Tests connectivity to Flexera services across US, EU, and APAC regions
- **Automatic CRL Discovery**: Dynamically discovers Certificate Revocation List (CRL) URLs from live SSL/TLS certificates

## CRL Auto-Discovery

The script automatically discovers CRL URLs from the following Flexera services:
- app.flexera.com
- login.flexera.com
- secure.flexera.com
- api.flexera.com
- beacon.flexnetmanager.com
- data.flexnetmanager.com

Only CRLs from trusted Certificate Authorities are included:
- *.amazontrust.com
- *.digicert.com
- *.lencr.org

Discovered CRLs are automatically added to the connectivity test if they are not already in the hardcoded list, ensuring comprehensive certificate revocation checking.

## Requirements

- Windows PowerShell 5.1 or PowerShell Core 6.0+
- Administrator privileges (required for TLS checks and .NET Framework installation)

## Usage

Run the script with administrator privileges:

```powershell
.\FlexeraOne-PreReqCheck.ps1
```
