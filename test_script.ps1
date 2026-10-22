Write-Host "AMSI bypass fired"
Write-Host "Current user: $env:USERNAME"
Write-Host "Host: $env:COMPUTERNAME"
Get-Process | Select-Object -First 3 | Format-Table Name, Id