$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/gallery-download.ps1"

$release = 'https://github.com/runestubbe/Crinkler/releases/download/v3.0b'
$archive = Save-GalleryTool "$release/crinkler30b.zip" `
    '14017536cf7bbc908f607260d5be30f56d8df182a0fd8fcead750e771f40888a'
$tools = New-Item -ItemType Directory -Path generated/gallery-tools/crinkler-3.0b -Force
Expand-Archive -LiteralPath $archive -DestinationPath $tools.FullName -Force
$linker = Join-Path $tools.FullName 'crinkler30b/Win32/Crinkler.exe'
$sdk = Get-ChildItem -Path "${env:ProgramFiles(x86)}/Windows Kits/10/Lib/*/um/x86/kernel32.lib" |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not (Test-Path -LiteralPath $linker) -or -not $sdk) {
    throw 'Crinkler or the x86 Windows SDK import library is missing.'
}
$object = Join-Path $tools.FullName 'hello-crinkler.obj'
clang --target=i686-pc-windows-msvc -c samples/gallery/hello-crinkler.s -o $object
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$output = New-Item -ItemType Directory -Path generated/gallery -Force
# The COFF symbol is _start. Crinkler looks it up by its undecorated name.
& $linker '/ENTRY:start' '/SUBSYSTEM:WINDOWS' '/COMPMODE:FAST' '/HASHTRIES:1' `
    "/OUT:$($output.FullName)\hello-crinkler.exe" $object $sdk.FullName
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item -LiteralPath (Join-Path $tools.FullName 'crinkler30b/LICENSE.txt') `
    -Destination (Join-Path $output.FullName 'crinkler-license.txt')
