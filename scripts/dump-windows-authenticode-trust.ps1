param(
  [string]$OutputPath = (Join-Path $PSScriptRoot "..\analyzers\pe\authenticode\windows-trust-store.generated.json")
)

$ErrorActionPreference = "Stop"
$warnings = [System.Collections.Generic.List[string]]::new()

function ConvertTo-TrustStoreCertificate {
  param(
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
    [string]$StoreName
  )

  [ordered]@{
    thumbprint  = $Certificate.Thumbprint.ToUpperInvariant()
    subject     = $Certificate.Subject
    issuer      = $Certificate.Issuer
    serialNumber = $Certificate.SerialNumber
    notBefore   = $Certificate.NotBefore.ToUniversalTime().ToString("o")
    notAfter    = $Certificate.NotAfter.ToUniversalTime().ToString("o")
    stores      = @($StoreName)
  }
}

function Read-CertificateStore {
  param([string]$StoreName)

  $storePath = "Cert:\LocalMachine\$StoreName"
  if (-not (Test-Path $storePath)) {
    $warnings.Add("Certificate store $storePath is not available on this runner.")
    return @()
  }

  try {
    $certificates = @(Get-ChildItem -Path $storePath -ErrorAction Stop)
  } catch {
    $warnings.Add("Certificate store $storePath could not be read: $($_.Exception.Message)")
    return @()
  }

  $certificates |
    Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] } |
    ForEach-Object { ConvertTo-TrustStoreCertificate -Certificate $_ -StoreName $StoreName }
}

function Merge-CertificateRecords {
  param([array]$Certificates)

  $recordsByThumbprint = [ordered]@{}
  foreach ($certificate in $Certificates) {
    if (-not $certificate.thumbprint) {
      continue
    }
    if (-not $recordsByThumbprint.Contains($certificate.thumbprint)) {
      $recordsByThumbprint[$certificate.thumbprint] = $certificate
      continue
    }
    $existing = $recordsByThumbprint[$certificate.thumbprint]
    $existing.stores = @($existing.stores + $certificate.stores | Sort-Object -Unique)
  }
  @($recordsByThumbprint.Values | Sort-Object -Property thumbprint)
}

# Microsoft documents the Windows Cert: provider and LocalMachine stores.
# Trusted roots are read from Root plus AuthRoot; untrusted/disallowed roots from Disallowed.
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/about/about_certificate_provider
# https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-trust
$trustedInput = @()
foreach ($storeName in @("Root", "AuthRoot")) {
  $trustedInput += @(Read-CertificateStore -StoreName $storeName)
}

$snapshot = [ordered]@{
  schemaVersion = 1
  generatedAt  = (Get-Date).ToUniversalTime().ToString("o")
  source       = "GitHub Actions windows-latest LocalMachine certificate stores"
  trustedCAs   = @(Merge-CertificateRecords -Certificates $trustedInput)
  revokedCAs   = @(Merge-CertificateRecords -Certificates @(Read-CertificateStore -StoreName "Disallowed"))
}

if ($warnings.Count -gt 0) {
  $snapshot.warnings = @($warnings)
}

$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutputPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$json = $snapshot | ConvertTo-Json -Depth 5
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($resolvedOutputPath, "$json$([Environment]::NewLine)", $utf8NoBom)
Write-Host "Wrote Windows Authenticode trust snapshot to $resolvedOutputPath"
