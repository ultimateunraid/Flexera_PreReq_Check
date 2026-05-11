<#!
.SYNOPSIS
    Checks system requirements including TLS versions, .NET Framework version, IIS features,
    and URL connectivity for Flexera One.

.DESCRIPTION
    This script verifies that required TLS versions are available on the system,
    checks if .NET Framework 4.8 or a compatible version is installed, validates
    required IIS features, and tests connectivity to required Flexera One URLs and
    certificate revocation servers.
    If .NET Framework 4.8 is not found, it prompts the user for installation.
    If IIS features are missing, they are listed in the summary and the user is
    prompted to install them.

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

# Color coding for output
function Write-Success {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Failure {
    param([string]$Message)
    Write-Host "[X] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "[i] $Message" -ForegroundColor Cyan
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

# Function to check TLS protocol availability
function Test-TlsProtocols {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Checking TLS Versions" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $supportedProtocols = [System.Net.ServicePointManager]::SecurityProtocol
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

# Function to get .NET Framework version
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
                    default { "Unknown version (Release: $release)" }
                }

                return @{
                    Installed = $true
                    Version   = $version
                    Release   = $release
                }
            }
        }

        return @{
            Installed = $false
            Version   = "Not installed"
            Release   = 0
        }
    }
    catch {
        Write-Failure "Error checking .NET Framework version: $_"
        return @{
            Installed = $false
            Version   = "Error"
            Release   = 0
        }
    }
}

# Function to check .NET Framework requirements
function Test-DotNetFramework {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Checking .NET Framework Version" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $dotNetInfo = Get-DotNetFrameworkVersion

    Write-Info "Detected .NET Framework: $($dotNetInfo.Version)"

    if ($dotNetInfo.Release -ge 528040) {
        Write-Success ".NET Framework 4.8 or compatible version is installed!"
        return $true
    } else {
        Write-Failure ".NET Framework 4.8 or compatible version is NOT installed."
        return $false
    }
}

# Function to download and install .NET Framework 4.8
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
        } elseif ($installProcess.ExitCode -eq 3010) {
            Write-Success ".NET Framework 4.8 installation completed!"
            Write-Warning "A system restart is required. Exit code: 3010"
            return $true
        } else {
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

# Function to check required IIS features
# Returns an array of missing feature objects, or $null if check is not applicable on this OS.
function Get-MissingIisFeatures {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Checking IIS Features" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $requiredFeatures = @(
        'Web-Server',           # IIS Web Server
        'Web-Asp-Net45',        # ASP.NET 4.5
        'Web-Net-Ext45',        # .NET Extensibility 4.5
        'Web-ISAPI-Ext',        # ISAPI Extensions
        'Web-Http-Errors',      # HTTP Errors
        'Web-Static-Content',   # Static Content
        'Web-Http-Logging',     # HTTP Logging
        'Web-Dyn-Compression',  # Dynamic Content Compression
        'Web-Stat-Compression', # Static Content Compression
        'Web-Basic-Auth',       # Basic Authentication
        'Web-Windows-Auth',     # Windows Authentication
        'Web-Mgmt-Console',     # IIS Management Console
        'Web-Mgmt-Service'      # IIS Management Service
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
            } else {
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
    } else {
        Write-Warning "$($missing.Count) required IIS feature(s) are not installed."
    }

    return $missing
}

# Function to install missing IIS features
function Install-IisFeatures {
    param(
        [object[]]$MissingFeatures
    )

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
        } else {
            Write-Failure "IIS feature installation reported a failure. Review output above."
        }
    }
    catch {
        Write-Failure "Error installing IIS features: $_"
    }
}

# Function to test URL connectivity
function Test-UrlConnectivity {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Checking URL Connectivity" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Category values: "Prod", "UAT", "Certificate", "Monitoring"
    $urlList = @(
        # ── Production — Flexera One US ──────────────────────────────────────
        @{ Hostname = "app.flexera.com";                  Path = $null; Required = $false; Category = "Prod"; Region = "US"   },
        @{ Hostname = "api.flexera.com";                  Path = $null; Required = $false; Category = "Prod"; Region = "US"   },
        @{ Hostname = "login.flexera.com";                Path = $null; Required = $false; Category = "Prod"; Region = "US"   },
        @{ Hostname = "secure.flexera.com";               Path = $null; Required = $false; Category = "Prod"; Region = "US"   },
        @{ Hostname = "beacon.flexnetmanager.com";        Path = $null; Required = $false; Category = "Prod"; Region = "US"   },
        @{ Hostname = "data.flexnetmanager.com";          Path = $null; Required = $false; Category = "Prod"; Region = "US"   },

        # ── Production — Flexera One EU ──────────────────────────────────────
        @{ Hostname = "app.flexera.eu";                   Path = $null; Required = $false; Category = "Prod"; Region = "EU"   },
        @{ Hostname = "api.flexera.eu";                   Path = $null; Required = $false; Category = "Prod"; Region = "EU"   },
        @{ Hostname = "login.flexera.eu";                 Path = $null; Required = $false; Category = "Prod"; Region = "EU"   },
        @{ Hostname = "secure.flexera.eu";                Path = $null; Required = $false; Category = "Prod"; Region = "EU"   },
        @{ Hostname = "beacon.flexnetmanager.eu";         Path = $null; Required = $false; Category = "Prod"; Region = "EU"   },
        @{ Hostname = "data.flexnetmanager.eu";           Path = $null; Required = $false; Category = "Prod"; Region = "EU"   },

        # ── Production — Flexera One APAC ────────────────────────────────────
        @{ Hostname = "app.flexera.au";                   Path = $null; Required = $false; Category = "Prod"; Region = "APAC" },
        @{ Hostname = "api.flexera.au";                   Path = $null; Required = $false; Category = "Prod"; Region = "APAC" },
        @{ Hostname = "login.flexera.au";                 Path = $null; Required = $false; Category = "Prod"; Region = "APAC" },
        @{ Hostname = "secure.flexera.au";                Path = $null; Required = $false; Category = "Prod"; Region = "APAC" },
        @{ Hostname = "beacon.flexnetmanager.au";         Path = $null; Required = $false; Category = "Prod"; Region = "APAC" },
        @{ Hostname = "data.flexnetmanager.au";           Path = $null; Required = $false; Category = "Prod"; Region = "APAC" },

        # ── UAT — Flexera One US ─────────────────────────────────────────────
        @{ Hostname = "beacon.uat.flexnetmanager.com";    Path = $null; Required = $false; Category = "UAT";  Region = "US"   },
        @{ Hostname = "data.uat.flexnetmanager.com";      Path = $null; Required = $false; Category = "UAT";  Region = "US"   },

        # ── UAT — Flexera One EU ─────────────────────────────────────────────
        @{ Hostname = "beacon.uat.flexnetmanager.eu";     Path = $null; Required = $false; Category = "UAT";  Region = "EU"   },
        @{ Hostname = "data.uat.flexnetmanager.eu";       Path = $null; Required = $false; Category = "UAT";  Region = "EU"   },

        # ── UAT — Flexera One APAC ───────────────────────────────────────────
        @{ Hostname = "beacon.uat.flexnetmanager.au";     Path = $null; Required = $false; Category = "UAT";  Region = "APAC" },
        @{ Hostname = "data.uat.flexnetmanager.au";       Path = $null; Required = $false; Category = "UAT";  Region = "APAC" },

        # ── Performance Monitoring ───────────────────────────────────────────
        @{ Hostname = "js-agent.newrelic.com";            Path = $null; Required = $false; Category = "Monitoring"; Region = "N/A" },
        @{ Hostname = "bam.nr-data.net";                  Path = $null; Required = $false; Category = "Monitoring"; Region = "N/A" },

        # ── Certificate Revocation Lists (CRL) and OCSP — Amazon Trust ──────
        @{ Hostname = "crl.r2m02.amazontrust.com";        Path = "/r2m02.crl";               Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl.sca1b.amazontrust.com";        Path = "/sca1b.crl";               Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crt.sca1b.amazontrust.com";        Path = "/sca1b.crt";               Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "ocsp.sca1b.amazontrust.com";       Path = $null;                      Required = $true; Category = "Certificate"; Region = "N/A" },

        # ── Certificate Revocation Lists (CRL) — DigiCert ───────────────────
        @{ Hostname = "crl3.digicert.com";                Path = "/ssca-sha2-g6.crl";        Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl4.digicert.com";                Path = "/ssca-sha2-g6.crl";        Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl3.digicert.com";                Path = "/DigiCertGlobalRootCA.crl"; Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl4.digicert.com";                Path = "/DigiCertGlobalRootCA.crl"; Required = $true; Category = "Certificate"; Region = "N/A" },

        # ── Certificate Revocation List (CRL) — Let's Encrypt ───────────────
        @{ Hostname = "x1.c.lencr.org";                   Path = $null;                      Required = $true; Category = "Certificate"; Region = "N/A" }
    )

    $requiredUrlsOk = $true
    $failedUrls     = @()

    $prodRegions = @{
        "US"   = @{ Total = 0; Success = 0 }
        "EU"   = @{ Total = 0; Success = 0 }
        "APAC" = @{ Total = 0; Success = 0 }
    }
    $uatRegions = @{
        "US"   = @{ Total = 0; Success = 0 }
        "EU"   = @{ Total = 0; Success = 0 }
        "APAC" = @{ Total = 0; Success = 0 }
    }
    $certificateStatus = @{ Total = 0; Success = 0 }
    $monitoringStatus  = @{ Total = 0; Success = 0 }

    foreach ($urlInfo in $urlList) {
        $hostname   = $urlInfo.Hostname
        $path       = $urlInfo.Path
        $isRequired = $urlInfo.Required
        $category   = $urlInfo.Category
        $region     = $urlInfo.Region

        if ($category -eq "Prod" -and $prodRegions.ContainsKey($region)) {
            $prodRegions[$region].Total++
        } elseif ($category -eq "UAT" -and $uatRegions.ContainsKey($region)) {
            $uatRegions[$region].Total++
        } elseif ($category -eq "Certificate") {
            $certificateStatus.Total++
        } elseif ($category -eq "Monitoring") {
            $monitoringStatus.Total++
        }

        $statusText = if ($isRequired) { "[REQUIRED]" } else { "[OPTIONAL]" }
        $target     = if ($path) { "${hostname}${path}" } else { $hostname }
        Write-Host "`nTesting: $target $statusText" -ForegroundColor Cyan

        $port = if ($category -eq "Certificate") { 80 } else { 443 }

        try {
            $tcpTest = Test-NetConnection -ComputerName $hostname -Port $port -WarningAction SilentlyContinue -ErrorAction Stop

            if ($tcpTest.TcpTestSucceeded) {
                Write-Success "$target is reachable on port $port"

                if ($category -eq "Prod" -and $prodRegions.ContainsKey($region)) {
                    $prodRegions[$region].Success++
                } elseif ($category -eq "UAT" -and $uatRegions.ContainsKey($region)) {
                    $uatRegions[$region].Success++
                } elseif ($category -eq "Certificate") {
                    $certificateStatus.Success++
                } elseif ($category -eq "Monitoring") {
                    $monitoringStatus.Success++
                }
            } else {
                if ($isRequired) {
                    Write-Failure "$target is NOT reachable on port $port"
                    $requiredUrlsOk = $false
                    $failedUrls += "http://${target}"
                } else {
                    Write-Warning "$target is NOT reachable on port $port"
                }
            }
        }
        catch {
            if ($isRequired) {
                Write-Failure "Error testing ${target}: $_"
                $requiredUrlsOk = $false
                $failedUrls += "http://${target}"
            } else {
                Write-Warning "Error testing ${target}: $_"
            }
        }
    }

    # ── Production regional summary ───────────────────────────────────────────
    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host "Production — Regional Access Summary" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan

    foreach ($region in @("US", "EU", "APAC")) {
        $success = $prodRegions[$region].Success
        $total   = $prodRegions[$region].Total
        if ($success -gt 0) {
            Write-Success "$region Region: Working ($success of $total reachable)"
        } else {
            Write-Failure "$region Region: Not Working (0 of $total reachable)"
        }
    }

    # ── UAT regional summary ──────────────────────────────────────────────────
    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host "UAT — Regional Access Summary" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan

    foreach ($region in @("US", "EU", "APAC")) {
        $success = $uatRegions[$region].Success
        $total   = $uatRegions[$region].Total
        if ($success -gt 0) {
            Write-Success "$region UAT: Working ($success of $total reachable)"
        } elseif ($total -gt 0) {
            Write-Warning "$region UAT: Not reachable (0 of $total) — optional"
        }
    }

    # ── Monitoring summary ────────────────────────────────────────────────────
    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host "Performance Monitoring Access" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan

    $monSuccess = $monitoringStatus.Success
    $monTotal   = $monitoringStatus.Total

    if ($monSuccess -eq $monTotal) {
        Write-Success "Monitoring endpoints: All reachable ($monSuccess of $monTotal) — optional"
    } else {
        Write-Warning "Monitoring endpoints: $monSuccess of $monTotal reachable — optional"
    }

    # ── Certificate / OCSP / CRL summary ─────────────────────────────────────
    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host "Certificate / OCSP / CRL Access" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan

    $certSuccess = $certificateStatus.Success
    $certTotal   = $certificateStatus.Total

    if ($certSuccess -eq $certTotal) {
        Write-Success "Certificate Revocation Access: All reachable ($certSuccess of $certTotal)"
    } elseif ($certSuccess -gt 0) {
        Write-Warning "Certificate Revocation Access: Partial ($certSuccess of $certTotal reachable)"
        $requiredUrlsOk = $false
    } else {
        Write-Failure "Certificate Revocation Access: Not Working (0 of $certTotal reachable)"
        $requiredUrlsOk = $false
    }

    Write-Host "`n" -NoNewline

    if ($requiredUrlsOk) {
        Write-Success "All required URLs are reachable!"
    } else {
        Write-Failure "One or more required URLs are NOT reachable!"
        Write-Info "Please check firewall settings and network connectivity."
    }

    return @{
        Ok         = $requiredUrlsOk
        FailedUrls = $failedUrls
    }
}

# Main execution
function Main {
    Write-Host "`n" -NoNewline
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "System Requirements Check" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta

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
        } else {
            Write-Info "Installation cancelled by user."
        }
    }

    # Check URL connectivity
    $urlResult = Test-UrlConnectivity
    $urlsOk    = $urlResult.Ok

    # Check IIS features
    $missingIis = Get-MissingIisFeatures
    # $null = check was skipped (non-server OS); @() = all present; non-empty = items missing
    if ($missingIis -eq $null) {
        $iisOk      = $null
        $iisSkipped = $true
    } else {
        $iisOk      = ($missingIis.Count -eq 0)
        $iisSkipped = $false
    }

    # ── Final Summary ─────────────────────────────────────────────────────────
    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host "Summary" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta

    if ($tlsOk) {
        Write-Success "TLS Versions: OK"
    } else {
        Write-Failure "TLS Versions: ISSUES DETECTED"
    }

    if ($dotNetOk) {
        Write-Success ".NET Framework: OK"
    } else {
        Write-Failure ".NET Framework: NOT COMPATIBLE"
    }

    if ($urlsOk) {
        Write-Success "URL Connectivity: OK"
    } else {
        Write-Failure "URL Connectivity: ISSUES DETECTED"
        if ($urlResult.FailedUrls.Count -gt 0) {
            Write-Host "  Failed required endpoints:" -ForegroundColor Red
            foreach ($u in $urlResult.FailedUrls) {
                Write-Host "    - $u" -ForegroundColor Red
            }
        }
    }

    if ($iisSkipped) {
        Write-Warning "IIS Features: SKIPPED (ServerManager not available — Windows Server required)"
    } elseif ($iisOk) {
        Write-Success "IIS Features: All required components present"
    } else {
        Write-Failure "IIS Features: $($missingIis.Count) component(s) missing"
        Write-Host "  Missing IIS features:" -ForegroundColor Red
        foreach ($f in $missingIis) {
            Write-Host "    - $($f.DisplayName) ($($f.Name))" -ForegroundColor Red
        }
    }

    Write-Host "`n"

    # Overall status
    $overallOk = $tlsOk -and $dotNetOk -and $urlsOk -and ($iisSkipped -or $iisOk)

    if ($overallOk) {
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Overall Status: ALL CHECKS PASSED" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
    } else {
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
        } else {
            Write-Info "IIS installation skipped."
        }
    }
}

# Run the script
Main
