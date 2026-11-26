$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/gallery-download.ps1"

$release = 'https://github.com/jrsoftware/issrc/releases/download/is-6_4_3'
$installer = Save-GalleryTool "$release/innosetup-6.4.3.exe" `
    'f3c42116542c4cc57263c5ba6c4feabfc49fe771f2f98a79d2f7628b8762723b'
$tools = New-Item -ItemType Directory -Path generated/gallery-tools/inno-6.4.3 -Force
$compiler = Join-Path $tools.FullName 'ISCC.exe'
if (-not (Test-Path -LiteralPath $compiler)) {
    $options = @('/PORTABLE=1', '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-',
        ('/DIR="{0}"' -f $tools.FullName))
    $install = Start-Process -FilePath $installer -ArgumentList $options `
        -WindowStyle Hidden -PassThru -Wait
    if ($install.ExitCode -ne 0) { throw "Inno Setup compiler install failed: $($install.ExitCode)" }
}
$output = New-Item -ItemType Directory -Path generated/gallery -Force
& $compiler "/O$($output.FullName)" '/Fhello-inno' samples/gallery/hello.iss
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item -LiteralPath (Join-Path $tools.FullName 'license.txt') `
    -Destination (Join-Path $output.FullName 'inno-setup-license.txt')
