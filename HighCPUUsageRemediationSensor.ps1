# Kernel, session, security and shell processes that must never be touched.
$protectedProcesses = @(
"System", "Idle", "Registry", "Memory Compression",
"smss", "csrss", "wininit", "winlogon", "services", "lsass", "svchost",
"dwm", "explorer",
"MsMpEng", "MpDefenderCoreService", "NisSrv", "SecurityHealthService"
)

# Background services safe to stop and leave stopped (demand-started, self-restart).
$deferrableServices = @("WSearch", "SysMain", "DiagTrack", "dosvc", "WerSvc")

# Low-risk services to keep running but restart if their host is spinning.
$restartableServices = @("Themes", "TabletInputService", "TrkWks", "WbioSrvc")

# Currently-running maintenance tasks safe to stop for this cycle (they re-trigger later).
$deferrableTasks = @(
"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
"\Microsoft\Windows\Maintenance\WinSAT",
"\Microsoft\Windows\Defrag\ScheduledDefrag"
)

# Structured report lines, one per lever, built regardless of whether that lever fired.
$reportLines  = New-Object System.Collections.Generic.List[string]
$actionsTaken = New-Object System.Collections.Generic.List[string]

# Top 5 CPU consumers at scan time (visibility only - includes protected processes too).
$top5CPUConsumers = New-Object System.Collections.Generic.List[string]

# One short line per lever that actually fired (skipped levers are not recorded).
$leverActions = New-Object System.Collections.Generic.List[string]

try {

$logicalProcessors = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
if (-not $logicalProcessors -or $logicalProcessors -lt 1) { $logicalProcessors = 1 }

# Single CPU snapshot shared by both the top-5 view and the actionable offender set,
# so the two rankings can never disagree due to sampling at different instants.
$processSnapshot = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
Where-Object {
$_.Name -ne "_Total" -and
$_.Name -ne "Idle" -and
$_.IDProcess -ne 0
}

# Top 5 CPU consumers for visibility only - deliberately unfiltered by the protected
# list, so the operator still sees a system process if that is what is spinning.
$top5Raw = $processSnapshot | Sort-Object PercentProcessorTime -Descending | Select-Object -First 5
foreach ($consumer in $top5Raw) {
$normalizedCpu = [math]::Round($consumer.PercentProcessorTime / $logicalProcessors, 1)
if($normalizedCpu -gt 0) {
$top5CPUConsumers.Add("$($consumer.Name) (PID $($consumer.IDProcess), ~$normalizedCpu% CPU)")
}
}

# Actionable offenders: non-protected processes above the per-core threshold, capped at 3.
$topOffenders = $processSnapshot |
Where-Object {
($protectedProcesses -notcontains ($_.Name -replace '#\d+$', '')) -and
$_.PercentProcessorTime -gt (5 * $logicalProcessors)
} |
Sort-Object PercentProcessorTime -Descending |
Select-Object -First 3

$offenderSummary = if ($topOffenders.Count -gt 0) {
($topOffenders | ForEach-Object {
$normalizedCpu = [math]::Round($_.PercentProcessorTime / $logicalProcessors, 1)
"$($_.Name) ($normalizedCpu%)"
}) -join ", "
} else {
"none above threshold"
}
$reportLines.Add("Scan: $logicalProcessors logical cores; top offenders: $offenderSummary")

#
# Lever 1 - Lower priority of the top offenders (contention lever).
#
$lever1Applied = $false
foreach ($offender in $topOffenders) {
try {
$process = Get-Process -Id $offender.IDProcess -ErrorAction Stop
if ($process.PriorityClass.ToString() -notin @("Idle", "BelowNormal")) {
$process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
$normalizedCpu = [math]::Round($offender.PercentProcessorTime / $logicalProcessors, 1)
$actionsTaken.Add("Lowered priority of $($process.ProcessName) (PID $($process.Id), ~$normalizedCpu% CPU)")
$lever1Applied = $true
}
}
catch { }
}
$reportLines.Add("1. Priority throttle : " + $(if ($lever1Applied) { "applied" } else { "skipped - no eligible offender" }))
if ($lever1Applied) { $leverActions.Add("Lowered priority of top CPU offenders") }

#
# Lever 2 - Confine a lone dominant hog to half the cores (absolute ceiling, no kill).
#
$lever2Applied = $false
$dominant = $topOffenders | Select-Object -First 1
if (
$null -ne $dominant -and
$logicalProcessors -ge 4 -and
$logicalProcessors -le 64 -and
($dominant.PercentProcessorTime / $logicalProcessors) -gt 70
) {
try {
$process = Get-Process -Id $dominant.IDProcess -ErrorAction Stop
$halfCores    = [math]::Max(1, [math]::Floor($logicalProcessors / 2))
$affinityMask = (1 -shl $halfCores) - 1
$process.ProcessorAffinity = [IntPtr]$affinityMask
$actionsTaken.Add("Confined $($process.ProcessName) (PID $($process.Id)) to $halfCores of $logicalProcessors cores")
$lever2Applied = $true
}
catch { }
}
$reportLines.Add("2. Core confinement  : " + $(if ($lever2Applied) { "applied" } else { "skipped - no dominant hog above 70%" }))
if ($lever2Applied) { $leverActions.Add("Confined top hog to half the cores") }

#
# Lever 3 - Pause deferrable background services (graceful stop, no -Force).
#
$lever3Applied = $false
foreach ($serviceName in $deferrableServices) {
try {
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $service -and $service.Status -eq "Running") {
Stop-Service -Name $serviceName -ErrorAction Stop
$actionsTaken.Add("Paused background service '$serviceName'")
$lever3Applied = $true
}
}
catch { }
}
$reportLines.Add("3. Background svcs   : " + $(if ($lever3Applied) { "applied" } else { "skipped - none running" }))
if ($lever3Applied) { $leverActions.Add("Paused deferrable background services") }

#
# Lever 4 - Stop currently-running deferrable maintenance tasks (reversible, re-triggers).
#
$lever4Applied = $false
try {
$runningTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
Where-Object {
$_.State -eq "Running" -and
($deferrableTasks -contains ($_.TaskPath + $_.TaskName))
}

foreach ($task in $runningTasks) {
try {
Stop-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction Stop
$actionsTaken.Add("Stopped maintenance task '$($task.TaskName)'")
$lever4Applied = $true
}
catch { }
}
}
catch { }
$reportLines.Add("4. Maintenance tasks : " + $(if ($lever4Applied) { "applied" } else { "skipped - none running" }))
if ($lever4Applied) { $leverActions.Add("Stopped deferrable maintenance tasks") }

#
# Lever 5 - Restart a low-risk service whose host is a top offender (clears spin loops).
#
$lever5Applied = $false
foreach ($offender in $topOffenders) {
try {
$hostedServices = Get-CimInstance Win32_Service -Filter "ProcessId = $($offender.IDProcess)" -ErrorAction SilentlyContinue

foreach ($hosted in $hostedServices) {
if ($restartableServices -contains $hosted.Name) {
try {
Restart-Service -Name $hosted.Name -ErrorAction Stop
$actionsTaken.Add("Restarted stuck service '$($hosted.Name)'")
$lever5Applied = $true
}
catch { }
}
}
}
catch { }
}
$reportLines.Add("5. Stuck-service scan: " + $(if ($lever5Applied) { "applied" } else { "skipped - none matched" }))
if ($lever5Applied) { $leverActions.Add("Restarted a stuck low-risk service") }

}
catch {
Write-Output "Failed; remediation could not complete. Error: $($_.Exception.Message)"
exit 1
}

Write-Output "actionsTaken: $($actionsTaken -join "`n")";
Write-Output "reportLines: $($reportLines -join "`n")";
Write-Output "top5CPUConsumers: $($top5CPUConsumers -join "`n")";
Write-Output "levelActions: $($leverActions -join "`n")";