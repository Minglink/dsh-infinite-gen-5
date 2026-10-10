[CmdletBinding()]
param([string]$PythonExe, [string]$Report)
$ErrorActionPreference = 'Stop'
$syntaxRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $PythonExe) { $PythonExe = Join-Path $syntaxRoot 'runtimes\ghidra\python\python.exe' }
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) { throw 'Provide the installed worker Python using -PythonExe.' }
$syntaxErrors = @()
Push-Location $syntaxRoot
try {
    $syntaxFiles = @(rg --files -g '*.js' -g '*.mjs' -g '*.py' -g '*.ps1' -g '!runtimes/**' -g '!third_party/**' -g '!worker/vendor/**' -g '!node_modules/**' -g '!adapters/ghidra/clientdeps/**')
    if ($LASTEXITCODE -ne 0) { throw 'Project source enumeration failed.' }
    $syntaxJs = @($syntaxFiles | Where-Object { $_ -match '\.(js|mjs)$' })
    $syntaxPy = @($syntaxFiles | Where-Object { $_ -match '\.py$' })
    $syntaxPs = @($syntaxFiles | Where-Object { $_ -match '\.ps1$' })
    foreach ($syntaxFile in $syntaxJs) {
        & node --check $syntaxFile
        if ($LASTEXITCODE -ne 0) { $syntaxErrors += $syntaxFile }
    }
    foreach ($syntaxFile in $syntaxPy) {
        & $PythonExe -m py_compile $syntaxFile
        if ($LASTEXITCODE -ne 0) { $syntaxErrors += $syntaxFile }
    }
    foreach ($syntaxFile in $syntaxPs) {
        $syntaxTokens = $null; $syntaxParseErrors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $syntaxRoot $syntaxFile), [ref]$syntaxTokens, [ref]$syntaxParseErrors)
        if ($syntaxParseErrors) { $syntaxErrors += $syntaxFile }
    }
    $syntaxResult = @{ok=($syntaxErrors.Count -eq 0);javascript=$syntaxJs.Count;python=$syntaxPy.Count;powershell=$syntaxPs.Count;errors=$syntaxErrors;powerShellVersion=$PSVersionTable.PSVersion.ToString()}
    $syntaxJson = $syntaxResult | ConvertTo-Json -Depth 4
    if ($Report) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($Report), $syntaxJson, [Text.UTF8Encoding]::new($false)) }
    Write-Output $syntaxJson
    if ($syntaxErrors.Count) { exit 1 }
} finally { Pop-Location }
