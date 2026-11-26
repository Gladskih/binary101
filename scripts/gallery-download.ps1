function Save-GalleryTool {
    param([string] $Uri, [string] $Sha256)

    $root = New-Item -ItemType Directory -Path generated/gallery-tools -Force
    $destination = Join-Path $root.FullName ([IO.Path]::GetFileName(([uri] $Uri).AbsolutePath))
    if (-not (Test-Path -LiteralPath $destination)) {
        Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $destination
    }
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $Sha256) {
        throw "SHA-256 mismatch for the gallery tool $destination"
    }
    return $destination
}
