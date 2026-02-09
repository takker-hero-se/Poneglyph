$env:PATH = "C:\Users\takke\.cargo\bin;" + $env:PATH
Set-Location "c:\Users\takke\OneDrive\ドキュメント\workspace\GolDRoger\poneglyph"
Write-Host "Building Poneglyph..."
cargo build --release
Write-Host "Exit: $LASTEXITCODE"
if ($LASTEXITCODE -eq 0) {
    Write-Host "Binary: target\release\poneglyph.exe"
}
