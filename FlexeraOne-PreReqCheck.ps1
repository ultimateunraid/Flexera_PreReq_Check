<#
.SYNOPSIS
    Checks system requirements including TLS versions, .NET Framework version, IIS features,
    and URL connectivity for Flexera One ITAM and IT Visibility (ITV).

.DESCRIPTION
    This script verifies TLS versions, .NET Framework 4.8, IIS features, and connectivity
    to required Flexera One endpoints.  At startup the script prompts for:
      1. Service — ITAM (IT Asset Management) or ITV (IT Visibility)
      2. Region  — US, EU, or AU
      3. UAT     — include UAT endpoints (ITAM only)
    Only endpoints relevant to the selected service and region are tested.

.NOTES
    Requires Administrator privileges for TLS checks, .NET Framework installation,
    and IIS feature installation.
#>

#Requires -RunAsAdministrator

# ── Execution Policy Check ────────────────────────────────────────────────────
# Sets Bypass for this process only — no permanent changes to the system.
$_effectivePolicy = Get-ExecutionPolicy -Scope Process
if ($_effectivePolicy -eq 'Undefined') { $_effectivePolicy = Get-ExecutionPolicy }
if ($_effectivePolicy -ne 'Bypass' -and $_effectivePolicy -ne 'Unrestricted') {
    Write-Host ''
    Write-Host "[!] Execution policy is '$_effectivePolicy'." -ForegroundColor Yellow
    Write-Host '    This script requires Bypass to run without interruption.' -ForegroundColor Yellow
    Write-Host '    This only applies to the current session — no permanent changes.' -ForegroundColor Yellow
    $response = Read-Host '    Set ExecutionPolicy to Unrestricted for this session? [Y/N]'
    if ($response -match '^[Yy]') {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force
        Write-Host '[OK] Execution policy set to Unrestricted for this session.' -ForegroundColor Green
        Write-Host ''
    } else {
        Write-Host '[!] Execution policy not changed. Script may fail on unsigned content.' -ForegroundColor Yellow
        Write-Host ''
    }
}
# ─────────────────────────────────────────────────────────────────────────────

# TLS versions to validate
$RequiredTlsVersions = @("Tls12")
$OptionalTlsVersions = @()

try {
    # TLS 1.3 is available in newer operating systems; treat as optional when present
    [void][System.Net.SecurityProtocolType]::Tls13
    $OptionalTlsVersions += "Tls13"
}
catch {
    # TLS 1.3 not supported in this environment
}

# ── Color-coded output helpers ─────────────────────────────────────────────────
function Write-Success { param([string]$Message); Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Failure { param([string]$Message); Write-Host "[X] $Message"  -ForegroundColor Red }
function Write-Info    { param([string]$Message); Write-Host "[i] $Message"  -ForegroundColor Cyan }
function Write-Warning { param([string]$Message); Write-Host "[!] $Message"  -ForegroundColor Yellow }

# ── TLS Protocol Check ────────────────────────────────────────────────────────
function Test-TlsProtocols {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Checking TLS Versions" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $supportedProtocols   = [System.Net.ServicePointManager]::SecurityProtocol
    $allRequiredAvailable = $true

    foreach ($protocolName in $RequiredTlsVersions) {
        $protocolEnum = [System.Net.SecurityProtocolType]::$protocolName
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = $supportedProtocols -bor $protocolEnum
            Write-Success "TLS $($protocolName.Substring(3)) is available"
        }
        catch {
            Write-Failure "TLS $($protocolName.Substring(3)) is NOT available"
            $allRequiredAvailable = $false
        }
    }

    foreach ($protocolName in $OptionalTlsVersions) {
        try {
            $protocolEnum = [System.Net.SecurityProtocolType]::$protocolName
            [System.Net.ServicePointManager]::SecurityProtocol = $supportedProtocols -bor $protocolEnum
            Write-Success "TLS $($protocolName.Substring(3)) is available (optional)"
        }
        catch {
            Write-Warning "TLS $($protocolName.Substring(3)) is NOT available (optional)"
        }
    }

    return $allRequiredAvailable
}

# ── .NET Framework Version Detection ─────────────────────────────────────────
function Get-DotNetFrameworkVersion {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"

        if (Test-Path $regPath) {
            $releaseKey = Get-ItemProperty -Path $regPath -Name Release -ErrorAction SilentlyContinue

            if ($releaseKey) {
                $release = $releaseKey.Release

                $version = switch ($release) {
                    { $_ -ge 533320 } { "4.8.1 or later"; break }
                    { $_ -ge 528040 } { "4.8"; break }
                    { $_ -ge 461808 } { "4.7.2"; break }
                    { $_ -ge 461308 } { "4.7.1"; break }
                    { $_ -ge 460798 } { "4.7"; break }
                    { $_ -ge 394802 } { "4.6.2"; break }
                    { $_ -ge 394254 } { "4.6.1"; break }
                    { $_ -ge 393295 } { "4.6"; break }
                    { $_ -ge 379893 } { "4.5.2"; break }
                    { $_ -ge 378675 } { "4.5.1"; break }
                    { $_ -ge 378389 } { "4.5"; break }
                    default           { "Unknown version (Release: $release)" }
                }

                return @{ Installed = $true;  Version = $version; Release = $release }
            }
        }

        return @{ Installed = $false; Version = "Not installed"; Release = 0 }
    }
    catch {
        Write-Failure "Error checking .NET Framework version: $_"
        return @{ Installed = $false; Version = "Error"; Release = 0 }
    }
}

function Test-DotNetFramework {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Checking .NET Framework Version" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $dotNetInfo = Get-DotNetFrameworkVersion
    Write-Info "Detected .NET Framework: $($dotNetInfo.Version)"

    if ($dotNetInfo.Release -ge 528040) {
        Write-Success ".NET Framework 4.8 or compatible version is installed!"
        return $true
    }
    else {
        Write-Failure ".NET Framework 4.8 or compatible version is NOT installed."
        return $false
    }
}

# ── .NET Framework 4.8 Installer ─────────────────────────────────────────────
function Install-DotNetFramework48 {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Installing .NET Framework 4.8" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $downloadUrl   = "https://go.microsoft.com/fwlink/?linkid=2088631"
    $installerPath = "$env:TEMP\ndp48-web.exe"

    try {
        Write-Info "Downloading .NET Framework 4.8 installer..."
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($downloadUrl, $installerPath)
        Write-Success "Download completed: $installerPath"

        Write-Info "Starting installation (this may take several minutes)..."
        Write-Warning "Your system may require a restart after installation."

        $installProcess = Start-Process -FilePath $installerPath -ArgumentList "/q", "/norestart" -Wait -PassThru

        if ($installProcess.ExitCode -eq 0) {
            Write-Success ".NET Framework 4.8 installation completed successfully!"
            Write-Warning "Please restart your computer to complete the installation."
            return $true
        }
        elseif ($installProcess.ExitCode -eq 3010) {
            Write-Success ".NET Framework 4.8 installation completed!"
            Write-Warning "A system restart is required. Exit code: 3010"
            return $true
        }
        else {
            Write-Failure "Installation failed with exit code: $($installProcess.ExitCode)"
            return $false
        }
    }
    catch {
        Write-Failure "Error during installation: $_"
        return $false
    }
    finally {
        if (Test-Path $installerPath) {
            Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# ── IIS Feature Check ─────────────────────────────────────────────────────────
# Returns an array of missing feature objects, or $null if check is not applicable.
function Get-MissingIisFeatures {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Checking IIS Features" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $requiredFeatures = @(
        'Web-Server',
        'Web-Asp-Net45',
        'Web-Net-Ext45',
        'Web-ISAPI-Ext',
        'Web-Http-Errors',
        'Web-Static-Content',
        'Web-Http-Logging',
        'Web-Dyn-Compression',
        'Web-Stat-Compression',
        'Web-Basic-Auth',
        'Web-Windows-Auth',
        'Web-Mgmt-Console',
        'Web-Mgmt-Service'
    )

    try {
        Import-Module ServerManager -ErrorAction Stop
    }
    catch {
        Write-Warning "ServerManager module not available — IIS check requires Windows Server. Skipping."
        return $null
    }

    $missing = @()

    foreach ($featureName in $requiredFeatures) {
        try {
            $featureObj = Get-WindowsFeature -Name $featureName -ErrorAction Stop
            if ($featureObj.Installed) {
                Write-Success "IIS: $($featureObj.DisplayName) ($featureName)"
            }
            else {
                Write-Warning "IIS MISSING: $($featureObj.DisplayName) ($featureName)"
                $missing += $featureObj
            }
        }
        catch {
            Write-Warning "Could not query IIS feature '$featureName': $_"
        }
    }

    if ($missing.Count -eq 0) {
        Write-Success "All required IIS features are installed."
    }
    else {
        Write-Warning "$($missing.Count) required IIS feature(s) are not installed."
    }

    return $missing
}

function Install-IisFeatures {
    param([object[]]$MissingFeatures)

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Installing Missing IIS Features" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    try {
        $featureNames = $MissingFeatures | ForEach-Object { $_.Name }
        Write-Info "Installing: $($featureNames -join ', ')"
        $result = Install-WindowsFeature -Name $featureNames -IncludeManagementTools
        if ($result.Success) {
            Write-Success "IIS feature installation completed successfully."
            if ($result.RestartNeeded -ne 'No') {
                Write-Warning "A system restart may be required to complete the installation."
            }
        }
        else {
            Write-Failure "IIS feature installation reported a failure. Review output above."
        }
    }
    catch {
        Write-Failure "Error installing IIS features: $_"
    }
}

# ── Run Configuration Prompt ──────────────────────────────────────────────────
function Get-RunConfiguration {
    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host "Configuration" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta

    # 1. Service selection
    Write-Host "`nSelect Service:" -ForegroundColor Cyan
    Write-Host "  1. ITAM  —  Flexera One IT Asset Management" -ForegroundColor White
    Write-Host "  2. ITV   —  Flexera IT Visibility" -ForegroundColor White
    do {
        $svcInput = Read-Host "Enter selection (1 or 2)"
    } while ($svcInput -ne '1' -and $svcInput -ne '2')

    if ($svcInput -eq '1') { $service = 'ITAM' } else { $service = 'ITV' }
    Write-Success "Service  : $service"

    # 2. Region selection
    Write-Host "`nSelect Region:" -ForegroundColor Cyan
    Write-Host "  1. US  —  North America" -ForegroundColor White
    Write-Host "  2. EU  —  Europe" -ForegroundColor White
    Write-Host "  3. AU  —  Asia-Pacific" -ForegroundColor White
    do {
        $regInput = Read-Host "Enter selection (1, 2, or 3)"
    } while ($regInput -ne '1' -and $regInput -ne '2' -and $regInput -ne '3')

    $regionMap = @{ '1' = 'US'; '2' = 'EU'; '3' = 'AU' }
    $region = $regionMap[$regInput]
    Write-Success "Region   : $region"

    # 3. UAT — ITAM only
    $includeUAT = $false
    if ($service -eq 'ITAM') {
        Write-Host "`nInclude UAT endpoints?" -ForegroundColor Cyan
        do {
            $uatInput = Read-Host "Enter selection (Y or N)"
        } while ($uatInput -notmatch '^[YyNn]$')

        $includeUAT = ($uatInput -match '^[Yy]$')
        if ($includeUAT) {
            Write-Success "UAT      : Included"
        }
        else {
            Write-Info    "UAT      : Not included"
        }
    }

    return @{
        Service    = $service
        Region     = $region
        IncludeUAT = $includeUAT
    }
}
# ─────────────────────────────────────────────────────────────────────────────

# ── ITAM URL List ─────────────────────────────────────────────────────────────
# Test order: Beacon (Required) → Data (Required) → CRL/OCSP (Required) →
#             UAT (Optional) → Portal/Auth (Optional) → Monitoring (Optional)
function Get-ItamUrls {
    return @(
        # ── 1. Beacon endpoints (Required) ───────────────────────────────────
        @{ Hostname = "beacon.flexnetmanager.com"; Path = $null; Required = $true;  Category = "Beacon"; Region = "US" },
        @{ Hostname = "beacon.flexnetmanager.eu";  Path = $null; Required = $true;  Category = "Beacon"; Region = "EU" },
        @{ Hostname = "beacon.flexnetmanager.au";  Path = $null; Required = $true;  Category = "Beacon"; Region = "AU" },

        # ── 2. Data endpoints (Required) ─────────────────────────────────────
        @{ Hostname = "data.flexnetmanager.com";   Path = $null; Required = $true;  Category = "Data";   Region = "US" },
        @{ Hostname = "data.flexnetmanager.eu";    Path = $null; Required = $true;  Category = "Data";   Region = "EU" },
        @{ Hostname = "data.flexnetmanager.au";    Path = $null; Required = $true;  Category = "Data";   Region = "AU" },

        # ── 3. Certificate Revocation Lists / OCSP (Required) ─────────────────
        @{ Hostname = "crl.r2m02.amazontrust.com";  Path = "/r2m02.crl";                Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl.sca1b.amazontrust.com";  Path = "/sca1b.crl";                Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crt.sca1b.amazontrust.com";  Path = "/sca1b.crt";                Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "ocsp.sca1b.amazontrust.com"; Path = $null;                       Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl3.digicert.com";          Path = "/ssca-sha2-g6.crl";         Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl4.digicert.com";          Path = "/ssca-sha2-g6.crl";         Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl3.digicert.com";          Path = "/DigiCertGlobalRootCA.crl";  Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl4.digicert.com";          Path = "/DigiCertGlobalRootCA.crl";  Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "x1.c.lencr.org";             Path = $null;                       Required = $true; Category = "Certificate"; Region = "N/A" },

        # ── 4. UAT endpoints (Optional) ───────────────────────────────────────
        @{ Hostname = "beacon.uat.flexnetmanager.com"; Path = $null; Required = $false; Category = "UAT"; Region = "US" },
        @{ Hostname = "data.uat.flexnetmanager.com";   Path = $null; Required = $false; Category = "UAT"; Region = "US" },
        @{ Hostname = "beacon.uat.flexnetmanager.eu";  Path = $null; Required = $false; Category = "UAT"; Region = "EU" },
        @{ Hostname = "data.uat.flexnetmanager.eu";    Path = $null; Required = $false; Category = "UAT"; Region = "EU" },
        @{ Hostname = "beacon.uat.flexnetmanager.au";  Path = $null; Required = $false; Category = "UAT"; Region = "AU" },
        @{ Hostname = "data.uat.flexnetmanager.au";    Path = $null; Required = $false; Category = "UAT"; Region = "AU" },

        # ── 5. Portal / Auth endpoints (Optional) ─────────────────────────────
        @{ Hostname = "app.flexera.com";    Path = $null; Required = $false; Category = "Portal"; Region = "US" },
        @{ Hostname = "api.flexera.com";    Path = $null; Required = $false; Category = "Portal"; Region = "US" },
        @{ Hostname = "login.flexera.com";  Path = $null; Required = $false; Category = "Portal"; Region = "US" },
        @{ Hostname = "secure.flexera.com"; Path = $null; Required = $false; Category = "Portal"; Region = "US" },
        @{ Hostname = "app.flexera.eu";     Path = $null; Required = $false; Category = "Portal"; Region = "EU" },
        @{ Hostname = "api.flexera.eu";     Path = $null; Required = $false; Category = "Portal"; Region = "EU" },
        @{ Hostname = "login.flexera.eu";   Path = $null; Required = $false; Category = "Portal"; Region = "EU" },
        @{ Hostname = "secure.flexera.eu";  Path = $null; Required = $false; Category = "Portal"; Region = "EU" },
        @{ Hostname = "app.flexera.au";     Path = $null; Required = $false; Category = "Portal"; Region = "AU" },
        @{ Hostname = "api.flexera.au";     Path = $null; Required = $false; Category = "Portal"; Region = "AU" },
        @{ Hostname = "login.flexera.au";   Path = $null; Required = $false; Category = "Portal"; Region = "AU" },
        @{ Hostname = "secure.flexera.au";  Path = $null; Required = $false; Category = "Portal"; Region = "AU" },

        # ── 6. Performance & Reliability Monitoring (Optional) ────────────────
        @{ Hostname = "js-agent.newrelic.com"; Path = $null; Required = $false; Category = "Monitoring"; Region = "N/A" },
        @{ Hostname = "bam.nr-data.net";       Path = $null; Required = $false; Category = "Monitoring"; Region = "N/A" }
    )
}
# ─────────────────────────────────────────────────────────────────────────────

# ── ITV URL List ──────────────────────────────────────────────────────────────
function Get-ItvUrls {
    return @(
        # ── Beacon endpoints (Required) ───────────────────────────────────────
        @{ Hostname = "beacon.flexera.com";                  Path = $null;               Required = $true;  Category = "Beacon"; Region = "US" },
        @{ Hostname = "us-west-2.beacons.flexeraeng.com";    Path = "/inventorybeacons"; Required = $true;  Category = "Beacon"; Region = "US" },
        @{ Hostname = "beacon.flexera.eu";                   Path = $null;               Required = $true;  Category = "Beacon"; Region = "EU" },
        @{ Hostname = "eu-central-1.beacons.flexeraeng.com"; Path = "/inventorybeacons"; Required = $true;  Category = "Beacon"; Region = "EU" },
        @{ Hostname = "beacon.flexera.au";                   Path = $null;               Required = $true;  Category = "Beacon"; Region = "AU" },

        # ── Certificate Revocation List (Required) ────────────────────────────
        @{ Hostname = "crl.sca1b.amazontrust.com"; Path = "/sca1b.crl"; Required = $true;  Category = "Certificate"; Region = "N/A" },

        # ── Performance & Reliability Monitoring (Optional) ───────────────────
        @{ Hostname = "js-agent.newrelic.com"; Path = $null; Required = $false; Category = "Monitoring"; Region = "N/A" },
        @{ Hostname = "bam.nr-data.net";       Path = $null; Required = $false; Category = "Monitoring"; Region = "N/A" }
    )
}
# ─────────────────────────────────────────────────────────────────────────────

# ── URL Connectivity Check ────────────────────────────────────────────────────
function Test-UrlConnectivity {
    param([hashtable]$Config)

    $service    = $Config.Service
    $region     = $Config.Region
    $includeUAT = $Config.IncludeUAT

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Checking URL Connectivity" -ForegroundColor Cyan
    Write-Host "Service: $service  |  Region: $region" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Select and filter the URL list to the chosen service and region
    if ($service -eq 'ITAM') {
        $allUrls = Get-ItamUrls
    }
    else {
        $allUrls = Get-ItvUrls
    }

    $filteredUrls = $allUrls | Where-Object {
        ($_.Region -eq $region -or $_.Region -eq 'N/A') -and
        ($includeUAT -or $_.Category -ne 'UAT')
    }

    # Per-category counters
    $counts = @{
        Beacon      = @{ Total = 0; Success = 0 }
        Data        = @{ Total = 0; Success = 0 }
        Certificate = @{ Total = 0; Success = 0 }
        UAT         = @{ Total = 0; Success = 0 }
        Portal      = @{ Total = 0; Success = 0 }
        Monitoring  = @{ Total = 0; Success = 0 }
    }

    $requiredUrlsOk = $true
    $failedUrls     = @()
    $lastCategory   = ""

    foreach ($urlInfo in $filteredUrls) {
        $hostname   = $urlInfo.Hostname
        $path       = $urlInfo.Path
        $isRequired = $urlInfo.Required
        $category   = $urlInfo.Category

        $counts[$category].Total = $counts[$category].Total + 1

        # Print a section header each time the category changes
        if ($category -ne $lastCategory) {
            $lastCategory = $category
            $sectionLabel = switch ($category) {
                "Beacon"      { "Beacon Endpoints [REQUIRED]" }
                "Data"        { "Data Endpoints [REQUIRED]" }
                "Certificate" { "Certificate Revocation Lists [REQUIRED]" }
                "UAT"         { "UAT Endpoints [OPTIONAL]" }
                "Portal"      { "Portal & Auth Endpoints [OPTIONAL]" }
                "Monitoring"  { "Performance & Reliability Monitoring [OPTIONAL]" }
                default       { $category }
            }
            Write-Host "`n--- $sectionLabel ---" -ForegroundColor Cyan
        }

        $target = if ($path) { "${hostname}${path}" } else { $hostname }
        Write-Host "`nTesting: $target" -ForegroundColor Cyan

        # CRL endpoints are HTTP (port 80); everything else is HTTPS (port 443)
        $port = if ($category -eq "Certificate") { 80 } else { 443 }

        try {
            $tcpTest = Test-NetConnection -ComputerName $hostname -Port $port -WarningAction SilentlyContinue -ErrorAction Stop

            if ($tcpTest.TcpTestSucceeded) {
                Write-Success "$target is reachable on port $port"
                $counts[$category].Success = $counts[$category].Success + 1
            }
            else {
                if ($isRequired) {
                    Write-Failure "$target is NOT reachable on port $port"
                    $requiredUrlsOk = $false
                    $failedUrls += $target
                }
                else {
                    Write-Warning "$target is NOT reachable on port $port"
                }
            }
        }
        catch {
            if ($isRequired) {
                Write-Failure "Error testing ${target}: $_"
                $requiredUrlsOk = $false
                $failedUrls += $target
            }
            else {
                Write-Warning "Error testing ${target}: $_"
            }
        }
    }

    # ── Connectivity Summary ──────────────────────────────────────────────────
    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host "Connectivity Summary  —  $service | $region" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan

    if ($counts.Beacon.Total -gt 0) {
        $s = $counts.Beacon.Success
        $t = $counts.Beacon.Total
        if ($s -eq $t) {
            Write-Success "Beacon Endpoints [Required]  : $s of $t reachable"
        }
        else {
            Write-Failure "Beacon Endpoints [Required]  : $s of $t reachable"
        }
    }

    if ($counts.Data.Total -gt 0) {
        $s = $counts.Data.Success
        $t = $counts.Data.Total
        if ($s -eq $t) {
            Write-Success "Data Endpoints   [Required]  : $s of $t reachable"
        }
        else {
            Write-Failure "Data Endpoints   [Required]  : $s of $t reachable"
        }
    }

    if ($counts.Certificate.Total -gt 0) {
        $s = $counts.Certificate.Success
        $t = $counts.Certificate.Total
        if ($s -eq $t) {
            Write-Success "CRL / OCSP       [Required]  : $s of $t reachable"
        }
        elseif ($s -gt 0) {
            Write-Warning "CRL / OCSP       [Required]  : $s of $t reachable (partial)"
            $requiredUrlsOk = $false
        }
        else {
            Write-Failure "CRL / OCSP       [Required]  : 0 of $t reachable"
            $requiredUrlsOk = $false
        }
    }

    if ($counts.UAT.Total -gt 0) {
        $s = $counts.UAT.Success
        $t = $counts.UAT.Total
        if ($s -eq $t) {
            Write-Success "UAT Endpoints    [Optional]  : $s of $t reachable"
        }
        else {
            Write-Warning "UAT Endpoints    [Optional]  : $s of $t reachable"
        }
    }

    if ($counts.Portal.Total -gt 0) {
        $s = $counts.Portal.Success
        $t = $counts.Portal.Total
        if ($s -eq $t) {
            Write-Success "Portal / Auth    [Optional]  : $s of $t reachable"
        }
        else {
            Write-Warning "Portal / Auth    [Optional]  : $s of $t reachable"
        }
    }

    if ($counts.Monitoring.Total -gt 0) {
        $s = $counts.Monitoring.Success
        $t = $counts.Monitoring.Total
        if ($s -eq $t) {
            Write-Success "Monitoring       [Optional]  : $s of $t reachable"
        }
        else {
            Write-Warning "Monitoring       [Optional]  : $s of $t reachable"
        }
    }

    Write-Host ""
    if ($requiredUrlsOk) {
        Write-Success "All required endpoints are reachable!"
    }
    else {
        Write-Failure "One or more required endpoints are NOT reachable!"
        Write-Info    "Please check firewall settings and network connectivity."
    }

    return @{
        Ok         = $requiredUrlsOk
        FailedUrls = $failedUrls
    }
}
# ─────────────────────────────────────────────────────────────────────────────

# ── Main Execution ────────────────────────────────────────────────────────────
function Main {
    Write-Host "`n" -NoNewline
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "Flexera One  —  System Requirements Check" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta

    # Prompt for service, region, and UAT preference before running any checks
    $config = Get-RunConfiguration

    # Check TLS versions
    $tlsOk = Test-TlsProtocols

    # Check .NET Framework
    $dotNetOk = Test-DotNetFramework

    if (-not $dotNetOk) {
        Write-Host "`n" -NoNewline
        $response = Read-Host "Would you like to install .NET Framework 4.8? (Y/N)"

        if ($response -eq 'Y' -or $response -eq 'y') {
            $installSuccess = Install-DotNetFramework48
            if ($installSuccess) { $dotNetOk = $true }
        }
        else {
            Write-Info "Installation cancelled by user."
        }
    }

    # Check URL connectivity for the selected service and region
    $urlResult = Test-UrlConnectivity -Config $config
    $urlsOk    = $urlResult.Ok

    # Check IIS features
    $missingIis = Get-MissingIisFeatures
    # $null = check was skipped (non-server OS); @() = all present; non-empty = items missing
    if ($missingIis -eq $null) {
        $iisOk      = $null
        $iisSkipped = $true
    }
    else {
        $iisOk      = ($missingIis.Count -eq 0)
        $iisSkipped = $false
    }

    # ── Final Summary ──────────────────────────────────────────────────────────
    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host "Summary" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta

    if ($tlsOk) {
        Write-Success "TLS Versions     : OK"
    }
    else {
        Write-Failure "TLS Versions     : ISSUES DETECTED"
    }

    if ($dotNetOk) {
        Write-Success ".NET Framework   : OK"
    }
    else {
        Write-Failure ".NET Framework   : NOT COMPATIBLE"
    }

    if ($urlsOk) {
        Write-Success "URL Connectivity : OK ($($config.Service) | $($config.Region))"
    }
    else {
        Write-Failure "URL Connectivity : ISSUES DETECTED ($($config.Service) | $($config.Region))"
        if ($urlResult.FailedUrls.Count -gt 0) {
            Write-Host "  Failed required endpoints:" -ForegroundColor Red
            foreach ($u in $urlResult.FailedUrls) {
                Write-Host "    - $u" -ForegroundColor Red
            }
        }
    }

    if ($iisSkipped) {
        Write-Warning "IIS Features     : SKIPPED (ServerManager not available — Windows Server required)"
    }
    elseif ($iisOk) {
        Write-Success "IIS Features     : All required components present"
    }
    else {
        Write-Failure "IIS Features     : $($missingIis.Count) component(s) missing"
        Write-Host "  Missing IIS features:" -ForegroundColor Red
        foreach ($f in $missingIis) {
            Write-Host "    - $($f.DisplayName) ($($f.Name))" -ForegroundColor Red
        }
    }

    Write-Host "`n"

    $overallOk = $tlsOk -and $dotNetOk -and $urlsOk -and ($iisSkipped -or $iisOk)

    if ($overallOk) {
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Overall Status: ALL CHECKS PASSED" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
    }
    else {
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "Overall Status: SOME CHECKS FAILED" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
    }

    Write-Host "`n"

    # Prompt to install missing IIS features (after summary)
    if (-not $iisSkipped -and -not $iisOk) {
        $response = Read-Host "Would you like to install the missing IIS features now? (Y/N)"
        if ($response -eq 'Y' -or $response -eq 'y') {
            Install-IisFeatures -MissingFeatures $missingIis
        }
        else {
            Write-Info "IIS installation skipped."
        }
    }
}

# Run the script
Main
