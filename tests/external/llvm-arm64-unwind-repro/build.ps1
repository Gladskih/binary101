param([string]$Clang = "clang", [string]$LldLink = "lld-link")
$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    New-Item -ItemType Directory -Force out | Out-Null
    & $Clang --target=aarch64-pc-windows-msvc -c chained.s -o out/chained.obj
    if ($LASTEXITCODE -ne 0) { throw "Chained fixture assembly failed" }
    & $Clang --target=aarch64-pc-windows-msvc -c chained.s `
        "-Wa,-defsym,PACKED_CONTROL=1" -o out/packed.obj
    if ($LASTEXITCODE -ne 0) { throw "Packed control assembly failed" }
    & $Clang --target=aarch64-pc-windows-msvc -c directory.s -o out/directory.obj
    if ($LASTEXITCODE -ne 0) { throw "Directory fixture assembly failed" }
    foreach ($name in @("chained", "packed", "directory")) {
        & $LldLink /entry:main /subsystem:console /nodefaultlib /machine:arm64 `
            "/out:out/$name.exe" "out/$name.obj"
        if ($LASTEXITCODE -ne 0) { throw "$name fixture linking failed" }
    }
    & $LldLink /entry:main /subsystem:console /nodefaultlib /machine:arm64 `
        /merge:.tail=.pdata /out:out/merged.exe out/directory.obj
    if ($LASTEXITCODE -ne 0) { throw "Merged fixture linking failed" }
} finally {
    Pop-Location
}
