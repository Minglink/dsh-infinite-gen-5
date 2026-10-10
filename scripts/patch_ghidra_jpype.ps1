# Maintainer-only deterministic JPype 1.5.2 Unicode bootstrap shim build.
[CmdletBinding()]
param([string]$RuntimeRoot)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('RuntimeRoot')) { $RuntimeRoot = Join-Path $PSScriptRoot '..\runtimes\ghidra' }
$runtimeBase = [IO.Path]::GetFullPath($RuntimeRoot)
$patchBase = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\adapters\ghidra\jpype-patch'))
$runtimeFile = Join-Path $runtimeBase 'runtime.json'
$runtime = Get-Content -LiteralPath $runtimeFile -Raw -Encoding UTF8 | ConvertFrom-Json
$upstreamJar = Join-Path $patchBase 'upstream\org.jpype.jar'
$upstreamSource = Join-Path $patchBase 'upstream\JPypeContext.java'
$patchedSource = Join-Path $patchBase 'JPypeContext.java'
$expectedJar = 'a8c993bccb81392102fca126d4d716605cbda2c6df2846d42c92dc3672bfd4f2'
$expectedSource = '29d79d69c508d9c520c13e29dbbd0d987bab3a586e93aaab91785dec901fc0f7'
function Get-PatchHash([string]$File) { (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant() }
if ((Get-PatchHash $upstreamJar) -ne $expectedJar -or (Get-PatchHash $upstreamSource) -ne $expectedSource) {
    throw 'Pinned JPype 1.5.2 upstream patch inputs do not match their expected SHA-256.'
}
$javaPath = [IO.Path]::GetFullPath((Join-Path $runtimeBase $runtime.javaHome))
$runtimePrefix = $runtimeBase.TrimEnd('\') + '\'
if (-not $javaPath.StartsWith($runtimePrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'javaHome escapes runtime root' }
$javac = Join-Path $javaPath 'bin\javac.exe'
if (-not (Test-Path -LiteralPath $javac -PathType Leaf)) { throw 'Bundled JDK javac.exe is required for this maintainer build' }
$build = Join-Path ([IO.Path]::GetTempPath()) ('ig5-jpype-patch-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $build -Force | Out-Null
& $javac -encoding UTF-8 --release 8 -cp $upstreamJar -d $build $patchedSource
if ($LASTEXITCODE -ne 0) { throw "JPype Context javac failed: $LASTEXITCODE" }
$output = Join-Path $build 'org.jpype.jar'
Copy-Item -LiteralPath $upstreamJar -Destination $output
$classes = @(Get-ChildItem -LiteralPath (Join-Path $build 'org\jpype') -Filter 'JPypeContext*.class' -File)
if ($classes.Count -eq 0) { throw 'javac did not produce JPypeContext classes' }
# Use the bundled JDK's ZIP writer to preserve unmodified JAR payloads. A fixed
# timestamp makes rebuilding from the same pinned inputs byte reproducible.
$jarTool = Join-Path $javaPath 'bin\jar.exe'
& $jarTool --update --file $output --date=2020-01-01T00:00:00Z -C $build 'org/jpype'
if ($LASTEXITCODE -ne 0) { throw "JPype Context jar update failed: $LASTEXITCODE" }
$targetJar = Join-Path $runtimeBase 'python\pylib\org.jpype.jar'
$proof = [ordered]@{ patch='ig5-jpype-context-v1'; version='1.5.2'; property='ig5.jpype.native_filename';
    nativeFilename='_jpype.cp312-win_amd64.pyd'; upstreamSource='https://raw.githubusercontent.com/jpype-project/jpype/v1.5.2/native/java/org/jpype/JPypeContext.java';
    upstreamSourceSha256=$expectedSource; upstreamJarSha256=$expectedJar; patchedJarSha256=(Get-PatchHash $output);
    patchedSourceSha256=(Get-PatchHash $patchedSource); patchSha256=(Get-PatchHash (Join-Path $patchBase 'unicode-bootstrap.patch'));
    sourceRoot='licenses/ig5-jpype-bootstrap' }
$licenseRoot = Join-Path $runtimeBase $proof.sourceRoot
New-Item -ItemType Directory -Path $licenseRoot -Force | Out-Null
foreach ($name in @('LICENSE','UPSTREAM-NOTICE','NOTICE.txt','README.md','JPypeContext.java','unicode-bootstrap.patch')) {
    Copy-Item -LiteralPath (Join-Path $patchBase $name) -Destination (Join-Path $licenseRoot $name) -Force
}
Copy-Item -LiteralPath $upstreamSource -Destination (Join-Path $licenseRoot 'upstream-JPypeContext.java') -Force
Copy-Item -LiteralPath $output -Destination $targetJar -Force
$runtime | Add-Member -NotePropertyName jpypeBootstrap -NotePropertyValue $proof -Force
[IO.File]::WriteAllText($runtimeFile, ($runtime | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $licenseRoot 'provenance.json'), ($proof | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
Write-Output ('PATCHED_JAR_SHA256=' + $proof.patchedJarSha256)
Write-Output ('PATCH_BUILD_EVIDENCE=' + $build)
