param(
    [Parameter(Mandatory = $true)] [string] $NativeFormatSourceDirectory,
    [Parameter(Mandatory = $true)] [string] $ReadyToRunSourceDirectory
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$reference = Join-Path $PSScriptRoot 'aot-r2r-reference/Reference.csproj'
$tests = Join-Path $PSScriptRoot 'aot-r2r-reference-tests/Reference.Tests.csproj'
$nativeSources = (Resolve-Path -LiteralPath $NativeFormatSourceDirectory).Path
$readySources = (Resolve-Path -LiteralPath $ReadyToRunSourceDirectory).Path

foreach ($name in @('MdBinaryReader.cs', 'NativeMetadataReader.cs', 'DehydratedData.cs')) {
    if (-not (Test-Path -LiteralPath (Join-Path $nativeSources $name))) {
        throw "Native format source directory lacks $name"
    }
}
foreach ($name in @('NativeReader.cs', 'NativeArray.cs', 'DebugInfo.cs')) {
    if (-not (Test-Path -LiteralPath (Join-Path $readySources $name))) {
        throw "ReadyToRun source directory lacks $name"
    }
}

$properties = @(
    "-p:NativeFormatSourceDirectory=$nativeSources",
    "-p:ReadyToRunSourceDirectory=$readySources"
)
$buildOutput = @(dotnet build $tests -c Release @properties --no-incremental --verbosity quiet 2>&1)
$buildOutput | Write-Output
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# CA2022 remains visible for the unmodified upstream NativeReader. Reject it in
# any owned file even though MSBuild cannot assign WarningsNotAsErrors per source.
$ownedWarning = $buildOutput | Where-Object {
    $_ -match 'aot-r2r-reference(-tests)?[\\/][^\\/]+\.cs\(\d+,\d+\): warning CA2022'
}
if ($ownedWarning) { throw "Owned C# source emitted CA2022: $ownedWarning" }
dotnet run --no-build --project $tests -c Release @properties --verbosity quiet
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$previousNativeSources = $env:NativeFormatSourceDirectory
$previousReadySources = $env:ReadyToRunSourceDirectory
$env:NativeFormatSourceDirectory = $nativeSources
$env:ReadyToRunSourceDirectory = $readySources
Push-Location $root
try {
    $referenceFiles = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'aot-r2r-reference') -Filter '*.cs' |
        ForEach-Object { "tests/external/aot-r2r-reference/$($_.Name)" })
    $testFiles = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'aot-r2r-reference-tests') -Filter '*.cs' |
        ForEach-Object { "tests/external/aot-r2r-reference-tests/$($_.Name)" })
    dotnet format whitespace $reference --no-restore --verify-no-changes --include $referenceFiles
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet format style $reference --no-restore --verify-no-changes --include $referenceFiles
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet format analyzers $reference --no-restore --verify-no-changes --include $referenceFiles
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet format whitespace $tests --no-restore --verify-no-changes --include $testFiles
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet format style $tests --no-restore --verify-no-changes --include $testFiles
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet format analyzers $tests --no-restore --verify-no-changes --include $testFiles
    exit $LASTEXITCODE
}
finally {
    Pop-Location
    $env:NativeFormatSourceDirectory = $previousNativeSources
    $env:ReadyToRunSourceDirectory = $previousReadySources
}
