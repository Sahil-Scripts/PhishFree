# backend/test_urls.ps1
# Quick tests for /analyze/url endpoint

$urls = @(
    "http://httpbin.org/redirect/3", # multi-hop redirect
    "http://github.com",             # redirect to https://github.com
    "https://www.google.com",        # HTTPS with cert
    "http://example.com"             # plain HTTP, no cert
)

foreach ($u in $urls) {
    Write-Host "`n=== Testing $u ===" -ForegroundColor Cyan
    $body = '{"url": "' + $u + '"}'
    try {
        $res = Invoke-RestMethod -Uri http://127.0.0.1:5000/analyze/url `
            -Method POST `
            -Body $body `
            -ContentType "application/json"
        $res | ConvertTo-Json -Depth 5
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}
