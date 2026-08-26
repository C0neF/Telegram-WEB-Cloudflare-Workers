[CmdletBinding()]
param(
    [int]$TimeoutSeconds = 6,
    [string]$OutputPath = ''
)

$ErrorActionPreference = 'Stop'
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $scriptRoot '..\artifacts\telegram-wss-probe.json'
}
$hosts = @(
    'pluto.web.telegram.org',
    'venus.web.telegram.org',
    'aurora.web.telegram.org',
    'vesta.web.telegram.org',
    'flora.web.telegram.org'
)

function Invoke-WsUpgradeProbe {
    param(
        [Parameter(Mandatory)] [string]$HostName,
        [Parameter(Mandatory)] [string]$UserAgent,
        [Parameter(Mandatory)] [int]$Timeout
    )

    $started = [DateTimeOffset]::UtcNow
    $headerLines = @(
        'Connection: Upgrade',
        'Upgrade: websocket',
        'Sec-WebSocket-Version: 13',
        'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
        'Sec-WebSocket-Protocol: binary'
    )
    $arguments = @(
        '-sS', '--http1.1', '--connect-timeout', [string]$Timeout,
        '--max-time', [string]$Timeout, '-D', '-', '-o', 'NUL',
        '-A', $UserAgent
    )
    foreach ($header in $headerLines) {
        $arguments += @('-H', $header)
    }
    $arguments += "https://$HostName/apiws"

    $raw = @(& curl.exe @arguments 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    $joined = $raw -join "`n"
    $status = [regex]::Match($joined, '(?im)^HTTP/\S+\s+(\d{3})[^\r\n]*')
    $protocol = [regex]::Match($joined, '(?im)^sec-websocket-protocol:\s*([^\r\n]+)')
    $curlError = ($raw | Where-Object { $_ -match '^curl:\s' } | Select-Object -First 1)

    [pscustomobject]@{
        host = $HostName
        userAgent = $UserAgent
        startedAtUtc = $started.ToString('o')
        elapsedMs = ([DateTimeOffset]::UtcNow - $started).TotalMilliseconds
        curlExitCode = $exitCode
        httpStatus = if ($status.Success) { [int]$status.Groups[1].Value } else { $null }
        protocol = if ($protocol.Success) { $protocol.Groups[1].Value.Trim() } else { $null }
        curlError = $curlError
        rawHeaderLines = @($raw | Where-Object { $_ -match '^(HTTP/|sec-websocket-protocol:|upgrade:|connection:)' })
    }
}

$results = @($hosts | ForEach-Object {
    $hostName = $_
    $probe = Invoke-WsUpgradeProbe -HostName $hostName -UserAgent 'curl/validation-probe' -Timeout $TimeoutSeconds
    $complete = ($probe.httpStatus -eq 101 -and $probe.protocol -eq 'binary')
    if (-not $complete) {
        $fallback = Invoke-WsUpgradeProbe -HostName $hostName -UserAgent 'OAI-SearchBot/1.0' -Timeout $TimeoutSeconds
        $fallback | Add-Member -NotePropertyName initialProbe -NotePropertyValue $probe
        $probe = $fallback
        $probe | Add-Member -NotePropertyName usedAiCrawlerFallback -NotePropertyValue $true
    } else {
        $probe | Add-Member -NotePropertyName usedAiCrawlerFallback -NotePropertyValue $false
    }
    $probe
})

$results = @($results | Sort-Object host)
$dir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
$results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8

$results | Select-Object host, httpStatus, protocol, curlExitCode, usedAiCrawlerFallback, curlError | Format-Table -AutoSize
if (@($results | Where-Object { $_.httpStatus -ne 101 -or $_.protocol -ne 'binary' }).Count -gt 0) {
    exit 1
}
