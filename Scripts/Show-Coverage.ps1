$env:TEST_MODE = "1"
$config = New-PesterConfiguration
$config.Run.Path = ".\tests"
$config.Run.PassThru = $true
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = ".\entra-id-pre-provision-onespan-fx7.ps1"
$config.Output.Verbosity = "Normal"
$results = Invoke-Pester -Configuration $config

"Coverage: $([Math]::Round($results.CodeCoverage.CoveragePercent, 2))%"
$results.CodeCoverage.CommandsMissed | Select-Object Line, Command | Format-Table -AutoSize
