param(
    [Parameter(Mandatory)][string]$Rules,
    [Parameter(Mandatory)][string]$Python,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$checkout = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$rulesPath = (Resolve-Path -LiteralPath $Rules).Path
$pythonPath = (Resolve-Path -LiteralPath $Python).Path
$computer = $env:COMPUTERNAME.ToLowerInvariant()
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

Push-Location $checkout
try {
    & $pythonPath -c "import compression.zstd"
    if ($LASTEXITCODE -ne 0) { throw 'Coldcleaner needs Python 3.14 or newer with Zstandard support' }
    & $pythonPath -m coldcleaner check-rules --rules $rulesPath
    if ($LASTEXITCODE -ne 0) { throw 'Coldcleaner rules failed validation' }
} finally {
    Pop-Location
}

$arguments = "-X utf8 -m coldcleaner reclaim --rules `"$rulesPath`" --host $computer --local"
if (!$DryRun) { $arguments += ' --apply' }
$action = New-ScheduledTaskAction -Execute $pythonPath -Argument $arguments -WorkingDirectory $checkout
$at = [DateTime]::UtcNow.Date.AddHours(4).AddMinutes(30)
if ($at -le [DateTime]::UtcNow) { $at = $at.AddDays(1) }
$trigger = New-ScheduledTaskTrigger -Daily -At $at.ToLocalTime()
$trigger.StartBoundary = $at.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 6)
Register-ScheduledTask -TaskName Coldcleaner -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
