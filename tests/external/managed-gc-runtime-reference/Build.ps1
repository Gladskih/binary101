param(
    [Parameter(Mandatory = $true)][string]$SourceDirectory,
    [string]$OutputDirectory = "scan-results/managed-gc-runtime-reference"
)
$ErrorActionPreference = "Stop"
# SourceDirectory contains unmodified v10.0.0 sources downloaded from:
# https://raw.githubusercontent.com/dotnet/runtime/v10.0.0/src/coreclr/inc/gcinfodecoder.h
# https://raw.githubusercontent.com/dotnet/runtime/v10.0.0/src/coreclr/inc/gcinfotypes.h
# https://raw.githubusercontent.com/dotnet/runtime/v10.0.0/src/coreclr/vm/gcinfodecoder.cpp
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$gcOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path
Copy-Item -LiteralPath "$SourceDirectory/gcinfodecoder.h", "$SourceDirectory/gcinfotypes.h",
    "$SourceDirectory/gcinfodecoder.cpp" -Destination $gcOutput
Copy-Item -Path "$PSScriptRoot/*.cpp", "$PSScriptRoot/*.h" -Destination $gcOutput
$gcWslOutput = (& wsl.exe -e wslpath -a $gcOutput).Trim()
& wsl.exe -e g++ -std=c++20 -O2 -I $gcWslOutput "$gcWslOutput/main.cpp" -o "$gcWslOutput/reference-v4"
if ($LASTEXITCODE -ne 0) { throw "GC v4 reference build failed." }
& wsl.exe -e g++ -std=c++20 -O2 -DGC_REFERENCE_LEGACY -I $gcWslOutput "$gcWslOutput/main.cpp" -o "$gcWslOutput/reference-v3"
if ($LASTEXITCODE -ne 0) { throw "GC v3 reference build failed." }
