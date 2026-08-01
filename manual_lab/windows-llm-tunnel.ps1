[CmdletBinding()]
param(
    [string]$MacHost = $env:MANUAL_LAB_SSH_HOST,
    [int]$LocalPort = 11511,
    [int]$RemotePort = 11511,
    [switch]$Stop
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$runDirectory = Join-Path $projectRoot ".run\manual_lab"
$pidPath = Join-Path $runDirectory "windows-llm-tunnel.pid"

if ($Stop) {
    if (-not (Test-Path -LiteralPath $pidPath)) {
        Write-Output "No recorded Windows LLM tunnel."
        exit 0
    }
    $tunnelPid = [int](Get-Content -Raw -LiteralPath $pidPath)
    $process = Get-Process -Id $tunnelPid -ErrorAction SilentlyContinue
    if ($null -ne $process) {
        Stop-Process -Id $tunnelPid
        Write-Output "Stopped Windows LLM tunnel process $tunnelPid."
    }
    Remove-Item -LiteralPath $pidPath -ErrorAction SilentlyContinue
    exit 0
}

if ([string]::IsNullOrWhiteSpace($MacHost)) {
    throw "Pass -MacHost <ssh-host> or set MANUAL_LAB_SSH_HOST."
}

$listener = Get-NetTCPConnection -State Listen -LocalPort $LocalPort -ErrorAction SilentlyContinue
if ($null -ne $listener) {
    Write-Output "Port $LocalPort is already listening; no new tunnel was started."
    exit 0
}

New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null
$arguments = @(
    "-N",
    "-o", "BatchMode=yes",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=30",
    "-L", "${LocalPort}:127.0.0.1:${RemotePort}",
    $MacHost
)
$process = Start-Process -FilePath "ssh.exe" -ArgumentList $arguments -WindowStyle Hidden -PassThru
$process.Id | Set-Content -LiteralPath $pidPath -Encoding ascii

for ($attempt = 0; $attempt -lt 40; $attempt++) {
    Start-Sleep -Milliseconds 250
    if ($process.HasExited) {
        Remove-Item -LiteralPath $pidPath -ErrorAction SilentlyContinue
        throw "SSH tunnel exited with code $($process.ExitCode). Verify that 'ssh $MacHost' works without a password prompt."
    }
    $listener = Get-NetTCPConnection -State Listen -LocalPort $LocalPort -ErrorAction SilentlyContinue
    if ($null -ne $listener) {
        Write-Output "Windows LLM tunnel ready: http://127.0.0.1:$LocalPort/v1 (PID $($process.Id))."
        exit 0
    }
}

Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $pidPath -ErrorAction SilentlyContinue
throw "Timed out waiting for the SSH tunnel on port $LocalPort."
