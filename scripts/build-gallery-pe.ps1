$ErrorActionPreference = 'Stop'

$samples = [ordered]@{
    'c-msvc-x64-o2-mt' = 'hello-msvc-x64.exe'
    'assembly-masm-x86-link' = 'hello-masm-x86.exe'
    'go-windows-amd64-default' = 'hello-go-x64.exe'
    'csharp-framework-win-x64-release' = 'HelloCSharp.dll'
}

node --import tsx scripts/pe-disassembly-samples/index.ts `
    --output generated/gallery-pe-matrix --filter ($samples.Keys -join ',')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$summary = Get-Content -LiteralPath generated/gallery-pe-matrix/summary.json -Raw | ConvertFrom-Json
$output = New-Item -ItemType Directory -Path generated/gallery -Force
foreach ($id in $samples.Keys) {
    $result = $summary.results | Where-Object id -eq $id
    if ($result.kind -ne 'success') {
        throw "Gallery sample $id did not build. See generated/gallery-pe-matrix/summary.md."
    }
    $source = $result.outputPath
    if ($id -eq 'csharp-framework-win-x64-release') {
        # The matrix's EXE is the native apphost. The adjacent DLL contains the managed code.
        $source = Join-Path (Split-Path $source) 'HelloCSharp.dll'
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $output.FullName $samples[$id])
}
$goRoot = go env GOROOT
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item -LiteralPath (Join-Path $goRoot 'LICENSE') `
    -Destination (Join-Path $output.FullName 'go-windows-license.txt')
