# Fallback para Windows si aún no hay Python.
# En Kali: python3 server.py

param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8080
)

$root = $PSScriptRoot
$prefix = "http://${HostAddress}:${Port}/"
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($prefix)
$listener.Start()

Write-Host "========================================================"
Write-Host "  Auditor SecOps Console"
Write-Host "  Panel: $prefix"
Write-Host "  Ctrl+C para detener"
Write-Host "========================================================"

$mime = @{
    ".html" = "text/html; charset=utf-8"
    ".css"  = "text/css; charset=utf-8"
    ".js"   = "application/javascript; charset=utf-8"
    ".svg"  = "image/svg+xml"
    ".png"  = "image/png"
    ".ico"  = "image/x-icon"
    ".json" = "application/json"
    ".mp4"  = "video/mp4"
}

try {
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $path = [Uri]::UnescapeDataString($ctx.Request.Url.LocalPath)
        if ([string]::IsNullOrWhiteSpace($path) -or $path -eq "/") {
            $path = "/index.html"
        }
        $full = Join-Path $root ($path.TrimStart("/").Replace("/", [IO.Path]::DirectorySeparatorChar))
        $full = [IO.Path]::GetFullPath($full)

        if (-not $full.StartsWith([IO.Path]::GetFullPath($root))) {
            $ctx.Response.StatusCode = 403
            $ctx.Response.Close()
            continue
        }

        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            $ctx.Response.StatusCode = 404
            $bytes = [Text.Encoding]::UTF8.GetBytes("Not found")
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            $ctx.Response.Close()
            continue
        }

        $ext = [IO.Path]::GetExtension($full).ToLowerInvariant()
        $ctx.Response.ContentType = $(if ($mime.ContainsKey($ext)) { $mime[$ext] } else { "application/octet-stream" })
        $bytes = [IO.File]::ReadAllBytes($full)
        $ctx.Response.ContentLength64 = $bytes.Length
        $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $ctx.Response.Close()
        Write-Host ("[{0}] {1} {2}" -f (Get-Date -Format "HH:mm:ss"), $ctx.Request.HttpMethod, $path)
    }
}
finally {
    $listener.Stop()
    $listener.Close()
}
