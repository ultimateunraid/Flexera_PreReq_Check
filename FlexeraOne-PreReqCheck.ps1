<#!
.SYNOPSIS
    Checks system requirements including TLS versions, .NET Framework version, and URL connectivity for Flexera One.

.DESCRIPTION
    This script verifies that required TLS versions are available on the system,
    checks if .NET Framework 4.8 or a compatible version is installed, and tests
    connectivity to required Flexera One URLs and certificate revocation servers.
    If .NET Framework 4.8 is not found, it prompts the user for installation.

.NOTES
    Requires Administrator privileges for TLS checks and .NET Framework installation.
#>

#Requires -RunAsAdministrator

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

        # Test if we can enable the protocol without error
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
        # Check registry for .NET Framework 4.x versions
        $regPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"

        if (Test-Path $regPath) {
            $releaseKey = Get-ItemProperty -Path $regPath -Name Release -ErrorAction SilentlyContinue

            if ($releaseKey) {
                $release = $releaseKey.Release

                # .NET Framework version mapping based on Release DWORD
                # https://learn.microsoft.com/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
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
                    Version = $version
                    Release = $release
                }
            }
        }

        return @{
            Installed = $false
            Version = "Not installed"
            Release = 0
        }
    }
    catch {
        Write-Failure "Error checking .NET Framework version: $_"
        return @{
            Installed = $false
            Version = "Error"
            Release = 0
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

    # Check if .NET 4.8 or higher is installed (Release >= 528040)
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

    $downloadUrl = "https://go.microsoft.com/fwlink/?linkid=2088631"
    $installerPath = "$env:TEMP\ndp48-web.exe"

    try {
        Write-Info "Downloading .NET Framework 4.8 installer..."

        # Use WebClient for download with progress
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($downloadUrl, $installerPath)

        Write-Success "Download completed: $installerPath"

        Write-Info "Starting installation (this may take several minutes)..."
        Write-Warning "Your system may require a restart after installation."

        # Run installer silently with /quiet flag
        # /norestart prevents automatic restart
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
        # Clean up installer
        if (Test-Path $installerPath) {
            Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Function to test URL connectivity
function Test-UrlConnectivity {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Checking URL Connectivity" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Define all URLs with their categories
    $urlList = @(
        # Flexera One US
        @{ Hostname = "app.flexera.com"; Required = $false; Category = "Flexera"; Region = "US" },
        @{ Hostname = "api.flexera.com"; Required = $false; Category = "Flexera"; Region = "US" },
        @{ Hostname = "login.flexera.com"; Required = $false; Category = "Flexera"; Region = "US" },
        @{ Hostname = "secure.flexera.com"; Required = $false; Category = "Flexera"; Region = "US" },
        @{ Hostname = "beacon.flexnetmanager.com"; Required = $false; Category = "Flexera"; Region = "US" },
        @{ Hostname = "data.flexnetmanager.com"; Required = $false; Category = "Flexera"; Region = "US" },

        # Flexera One EU
        @{ Hostname = "app.flexera.eu"; Required = $false; Category = "Flexera"; Region = "EU" },
        @{ Hostname = "api.flexera.eu"; Required = $false; Category = "Flexera"; Region = "EU" },
        @{ Hostname = "login.flexera.eu"; Required = $false; Category = "Flexera"; Region = "EU" },
        @{ Hostname = "secure.flexera.eu"; Required = $false; Category = "Flexera"; Region = "EU" },
        @{ Hostname = "beacon.flexnetmanager.eu"; Required = $false; Category = "Flexera"; Region = "EU" },
        @{ Hostname = "data.flexnetmanager.eu"; Required = $false; Category = "Flexera"; Region = "EU" },

        # Flexera One APAC
        @{ Hostname = "app.flexera.au"; Required = $false; Category = "Flexera"; Region = "APAC" },
        @{ Hostname = "api.flexera.au"; Required = $false; Category = "Flexera"; Region = "APAC" },
        @{ Hostname = "login.flexera.au"; Required = $false; Category = "Flexera"; Region = "APAC" },
        @{ Hostname = "secure.flexera.au"; Required = $false; Category = "Flexera"; Region = "APAC" },
        @{ Hostname = "beacon.flexnetmanager.au"; Required = $false; Category = "Flexera"; Region = "APAC" },
        @{ Hostname = "data.flexnetmanager.au"; Required = $false; Category = "Flexera"; Region = "APAC" },

        # Certificate Revocation and OCSP
        @{ Hostname = "crl.r2m02.amazontrust.com"; Path = "/r2m02.crl"; Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl.sca1b.amazontrust.com"; Path = "/sca1b.crl"; Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crt.sca1b.amazontrust.com"; Path = "/sca1b.crt"; Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "ocsp.sca1b.amazontrust.com"; Path = $null; Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl3.digicert.com"; Path = "/ssca-sha2-g6.crl"; Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl4.digicert.com"; Path = "/ssca-sha2-g6.crl"; Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl3.digicert.com"; Path = "/DigiCertGlobalRootCA.crl"; Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "crl4.digicert.com"; Path = "/DigiCertGlobalRootCA.crl"; Required = $true; Category = "Certificate"; Region = "N/A" },
        @{ Hostname = "x1.c.lencr.org"; Path = $null; Required = $true; Category = "Certificate"; Region = "N/A" }
    )

    $requiredUrlsOk = $true
    $flexeraRegions = @{
        "US" = @{ Total = 0; Success = 0 }
        "EU" = @{ Total = 0; Success = 0 }
        "APAC" = @{ Total = 0; Success = 0 }
    }
    $certificateStatus = @{ Total = 0; Success = 0 }

    foreach ($urlInfo in $urlList) {
        $hostname = $urlInfo.Hostname
        $path = $urlInfo.Path
        $isRequired = $urlInfo.Required
        $category = $urlInfo.Category
        $region = $urlInfo.Region

        if ($category -eq "Flexera" -and $flexeraRegions.ContainsKey($region)) {
            $flexeraRegions[$region].Total++
        } elseif ($category -eq "Certificate") {
            $certificateStatus.Total++
        }

        $statusText = if ($isRequired) { "[REQUIRED]" } else { "[OPTIONAL]" }
        $target = if ($path) { "${hostname}${path}" } else { $hostname }
        Write-Host "`nTesting: $target $statusText" -ForegroundColor Cyan

        $port = if ($category -eq "Certificate") { 80 } else { 443 }

        try {
            $tcpTest = Test-NetConnection -ComputerName $hostname -Port $port -WarningAction SilentlyContinue -ErrorAction Stop

            if ($tcpTest.TcpTestSucceeded) {
                Write-Success "$target is reachable on port $port"

                # Track success
                if ($category -eq "Flexera" -and $flexeraRegions.ContainsKey($region)) {
                    $flexeraRegions[$region].Success++
                } elseif ($category -eq "Certificate") {
                    $certificateStatus.Success++
                }
            } else {
                if ($isRequired) {
                    Write-Failure "$target is NOT reachable on port $port"
                    $requiredUrlsOk = $false
                } else {
                    Write-Warning "$target is NOT reachable on port $port"
                }
            }
        }
        catch {
            if ($isRequired) {
                Write-Failure "Error testing $target : $_"
                $requiredUrlsOk = $false
            } else {
                Write-Warning "Error testing $target : $_"
            }
        }
    }

    # Display regional access summary
    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host "Regional Access Summary" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan

    foreach ($region in @("US", "EU", "APAC")) {
        $success = $flexeraRegions[$region].Success
        $total = $flexeraRegions[$region].Total

        if ($success -gt 0) {
            Write-Success "$region Region: Working ($success of $total reachable)"
        } else {
            Write-Failure "$region Region: Not Working (0 of $total reachable)"
        }
    }

    # Certificate endpoints
    Write-Host "`nCertificate and OCSP Access:" -ForegroundColor Yellow
    $certSuccess = $certificateStatus.Success
    $certTotal = $certificateStatus.Total
    if ($certSuccess -eq $certTotal) {
        Write-Success "Certificate Revocation Access: Working ($certSuccess of $certTotal reachable)"
    } else {
        if ($certSuccess -gt 0) {
            Write-Warning "Certificate Revocation Access: Partial ($certSuccess of $certTotal reachable)"
        } else {
            Write-Failure "Certificate Revocation Access: Not Working (0 of $certTotal reachable)"
        }
        $requiredUrlsOk = $false
    }

    Write-Host "`n" -NoNewline

    if ($requiredUrlsOk) {
        Write-Success "All required URLs are reachable!"
    } else {
        Write-Failure "One or more required URLs are NOT reachable!"
        Write-Info "Please check firewall settings and network connectivity."
    }

    return $requiredUrlsOk
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

    # If .NET Framework 4.8 is not installed, prompt for installation
    if (-not $dotNetOk) {
        Write-Host "`n" -NoNewline
        $response = Read-Host "Would you like to install .NET Framework 4.8? (Y/N)"

        if ($response -eq 'Y' -or $response -eq 'y') {
            $installSuccess = Install-DotNetFramework48

            if ($installSuccess) {
                $dotNetOk = $true
            }
        } else {
            Write-Info "Installation cancelled by user."
        }
    }

    # Check URL connectivity
    $urlsOk = Test-UrlConnectivity

    # Final summary
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
    }

    Write-Host "`n"

    # Overall status
    if ($tlsOk -and $dotNetOk -and $urlsOk) {
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Overall Status: ALL CHECKS PASSED" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
    } else {
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "Overall Status: SOME CHECKS FAILED" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
    }

    Write-Host "`n"
}

# Run the script
Main
