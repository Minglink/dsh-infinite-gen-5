param([Parameter(Mandatory)][string]$JavaHome, [Parameter(Mandatory)][string]$BuildRoot)
$ErrorActionPreference = 'Stop'
$JavaHome = [IO.Path]::GetFullPath($JavaHome)
$BuildRoot = [IO.Path]::GetFullPath($BuildRoot)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$package = [IO.Compression.ZipFile]::OpenRead((Join-Path $JavaHome 'lib\src.zip'))
try {
  $entry = $package.Entries | Where-Object FullName -EQ 'java.base/sun/nio/ch/PipeImpl.java'
  if (!$entry) { throw 'OpenJDK source package does not contain PipeImpl.java' }
  $reader = [IO.StreamReader]::new($entry.Open())
  try { $original = $reader.ReadToEnd() } finally { $reader.Dispose() }
} finally { $package.Dispose() }
$needle = 'Initializer initializer = new Initializer(sp, preferAfUnix);'
if (($original.Split($needle).Count - 1) -ne 1) { throw 'Unexpected OpenJDK PipeImpl source; refuse unverified shim' }
$patched = $original.Replace($needle, 'Initializer initializer = new Initializer(sp, false); // IG5 build-only TCP loopback')
$sourceRoot = Join-Path $BuildRoot 'src'
$classRoot = Join-Path $BuildRoot 'classes'
New-Item -ItemType Directory -Path (Join-Path $sourceRoot 'sun\nio\ch'),$classRoot -Force | Out-Null
$sourceFile = Join-Path $sourceRoot 'sun\nio\ch\PipeImpl.java'
[IO.File]::WriteAllText($sourceFile, $patched, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $BuildRoot 'PipeImpl.upstream.java'), $original, [Text.UTF8Encoding]::new($false))
& (Join-Path $JavaHome 'bin\javac.exe') --patch-module "java.base=$sourceRoot" -d $classRoot $sourceFile
if ($LASTEXITCODE -ne 0) { throw 'Build-only Java TCP pipe shim compilation failed' }
$legal = Join-Path $JavaHome 'legal\java.base'
foreach ($name in @('LICENSE','ADDITIONAL_LICENSE_INFO','ASSEMBLY_EXCEPTION')) {
  if (Test-Path -LiteralPath (Join-Path $legal $name)) { Copy-Item -LiteralPath (Join-Path $legal $name) -Destination (Join-Path $BuildRoot $name) -Force }
}
$proof = @{schemaVersion=1; scope='Maintainer Gradle processes only; packaged JDK and runtime worker are unchanged'; reason='Windows AF_UNIX NIO pipe connect fails with Invalid argument on this host; use the existing TCP loopback path instead'; upstreamSourceSHA256=(Get-FileHash -LiteralPath (Join-Path $BuildRoot 'PipeImpl.upstream.java') -Algorithm SHA256).Hash.ToLowerInvariant(); patchedSourceSHA256=(Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash.ToLowerInvariant(); classRoot=$classRoot; javaHome=$JavaHome; sourceLicense='OpenJDK GPL-2.0 with Classpath exception, source copyright retained'}
$proof | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $BuildRoot 'provenance.json') -Encoding utf8
Write-Output $classRoot
