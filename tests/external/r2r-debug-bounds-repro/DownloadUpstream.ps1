param(
    [string] $RuntimeRef = '0e45f6c8d90db0acaa0c8b671fc9b0f4da383a06'
)

$ErrorActionPreference = 'Stop'
$upstream = Join-Path $PSScriptRoot 'upstream'
$source = 'src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun'
$paths = @('NativeReader.cs', 'NibbleReader.cs', 'DebugInfo.cs', 'DebugInfoTypes.cs')
$paths += @('x86', 'Amd64', 'Arm', 'Arm64', 'LoongArch64', 'RiscV64') |
    ForEach-Object { "$_/Registers.cs" }
foreach ($path in $paths) {
    $destination = Join-Path $upstream $path
    New-Item -ItemType Directory -Force (Split-Path -Parent $destination) | Out-Null
    Invoke-WebRequest -UseBasicParsing -Uri (
        "https://raw.githubusercontent.com/dotnet/runtime/$RuntimeRef/$source/$path"
    ) -OutFile $destination
}
# Current NativeReader imports ObjectWriter and calls its LEB128 reader.
# The v10 reader does not need this dependency.
if ($RuntimeRef -ne 'v10.0.0') {
    Invoke-WebRequest -UseBasicParsing -Uri (
        "https://raw.githubusercontent.com/dotnet/runtime/$RuntimeRef/" +
        'src/coreclr/tools/Common/Compiler/ObjectWriter/Dwarf/DwarfHelper.cs'
    ) -OutFile (Join-Path $upstream 'DwarfHelper.cs')
}
Write-Output "Downloaded unmodified dotnet/runtime sources at $RuntimeRef"
