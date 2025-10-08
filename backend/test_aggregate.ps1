# backend/test_aggregate.ps1
$tests = @(
    @{ id="phish_bank"; text="Dear Customer, verify your account immediately at http://secure-bank-login.example/ to avoid suspension." },
    @{ id="benign_meeting"; text="Hi team, meeting tomorrow at 10am. Agenda attached." },
    @{ id="phish_invoice"; text="Invoice attached: Invoice_8472.pdf. Please pay at http://example-payments.test/" },
    @{ id="url_only_github"; url="http://github.com" },
    @{ id="url_only_httpbin"; url="http://httpbin.org/redirect/3" }
)

foreach ($t in $tests) {
    $payload = @{}
    if ($t.text) { $payload.text = $t.text }
    if ($t.url) { $payload.url = $t.url }
    $json = ($payload | ConvertTo-Json -Compress)
    Write-Host "`n=== $($t.id) ===" -ForegroundColor Cyan
    try {
        $res = Invoke-RestMethod -Uri http://127.0.0.1:5000/analyze/aggregate -Method POST -Body $json -ContentType "application/json"
        Write-Host ("Aggregate score: {0}  Label: {1}" -f $res.aggregate_score, $res.label)
        Write-Host ("Text score: {0}" -f ($res.text.score)) -ForegroundColor Yellow
        Write-Host ("URL score: {0}" -f ($res.url.score)) -ForegroundColor Yellow
        Write-Host "Combined reasons:"
        $res.combined_reasons | ForEach-Object { Write-Host " - $_" }
    } catch {
        Write-Host "Error calling API: $($_.Exception.Message)" -ForegroundColor Red
    }
}
