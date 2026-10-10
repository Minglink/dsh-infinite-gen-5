# Maintainer-only offline Ghidra local project path compatibility build.
[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [string]$ArtifactRoot = (Join-Path $env:USERPROFILE '.dsh\ig5\artifacts\ghidra-local-project-path-build')
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('RuntimeRoot')) { $RuntimeRoot = Join-Path $PSScriptRoot '..\runtimes\ghidra' }
$projectBase = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runtimeBase = [IO.Path]::GetFullPath($RuntimeRoot)
$runtime = Get-Content -LiteralPath (Join-Path $runtimeBase 'runtime.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$pythonPath = [IO.Path]::GetFullPath((Join-Path $runtimeBase $runtime.pythonExe))
if (-not $pythonPath.StartsWith($runtimeBase.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Build Python escapes the source runtime directory' }
$builder = Join-Path $projectBase 'adapters\ghidra\local-project-path\build_patch.py'
& $pythonPath -I -B $builder --project $projectBase --runtime-root $runtimeBase --artifact-root ([IO.Path]::GetFullPath($ArtifactRoot))
if ($LASTEXITCODE -ne 0) { throw "Ghidra local project path build failed: $LASTEXITCODE" }
