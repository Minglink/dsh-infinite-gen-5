param(
  [string]$SourceRoot = (Join-Path $PSScriptRoot '..\third_party\sources\ghidra-12.1.4'),
  [string]$BuildRoot = (Join-Path $env:USERPROFILE '.dsh\ig5\artifacts\ghidra-build\full-win-x64'),
  [string]$JavaHome = (Join-Path $PSScriptRoot '..\runtimes\ghidra\jdk-21.0.12.1+1'),
  [string]$GradleArchive,
  [string]$VsWherePath,
  [switch]$UseWindowsTcpPipe,
  [switch]$Offline,
  [int]$Workers = 4
)
$ErrorActionPreference = 'Stop'
$SourceRoot = [IO.Path]::GetFullPath($SourceRoot)
$BuildRoot = [IO.Path]::GetFullPath($BuildRoot)
$JavaHome = [IO.Path]::GetFullPath($JavaHome)
$gradleVersion = '9.7.1'
$gradleHash = 'acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a'
if (!(Test-Path -LiteralPath (Join-Path $JavaHome 'bin\javac.exe'))) { throw 'A complete JDK is required' }
if ((Get-Content -LiteralPath (Join-Path $SourceRoot 'Ghidra\application.properties') -Raw) -notmatch '(?m)^application.version=12\.1\.4\s*$') { throw 'Expected pinned Ghidra 12.1.4 source baseline' }
if ($BuildRoot.StartsWith($SourceRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Build output must remain outside the immutable source baseline' }
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
if (!$GradleArchive) { $GradleArchive = Join-Path $BuildRoot "gradle-$gradleVersion-bin.zip" }
$GradleArchive = [IO.Path]::GetFullPath($GradleArchive)
if (!(Test-Path -LiteralPath $GradleArchive)) {
  if ($Offline) { throw 'Offline build requires the pinned Gradle archive and prepared dependency cache' }
  & curl.exe --fail --location --retry 3 --output $GradleArchive "https://downloads.gradle.org/distributions/gradle-$gradleVersion-bin.zip"
  if ($LASTEXITCODE -ne 0) { throw 'Gradle acquisition failed' }
}
if ((Get-FileHash -LiteralPath $GradleArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $gradleHash) { throw 'Pinned Gradle archive SHA-256 mismatch' }
$gradleRoot = Join-Path $BuildRoot "gradle-$gradleVersion"
if (!(Test-Path -LiteralPath (Join-Path $gradleRoot 'bin\gradle.bat'))) { Expand-Archive -LiteralPath $GradleArchive -DestinationPath $BuildRoot }
$workspace = Join-Path $BuildRoot 'workspace'
robocopy $SourceRoot $workspace /E /FFT /XJ /NP /NFL /NDL /R:2 /W:1
if ($LASTEXITCODE -gt 7) { throw 'Pinned source copy failed' }
# Upstream generates gradle.lockfile after the first --write-locks build, but
# its IP scan treats those generated lock files as uncategorised source on the
# next build. Keep license checks enabled and exclude only that exact generated
# filename in the disposable workspace; immutable source remains unchanged.
$ipPath = Join-Path $workspace 'gradle\support\ip.gradle'
$ipOriginal = [IO.File]::ReadAllText((Join-Path $SourceRoot 'gradle\support\ip.gradle'))
$ipNeedle = 'exclude "build.gradle"'
if (($ipOriginal.Split($ipNeedle).Count - 1) -ne 1) { throw 'Unexpected upstream IP scan; refuse build overlay' }
$ipPatched = $ipOriginal.Replace($ipNeedle, $ipNeedle + "`n`t`texclude `"**/gradle.lockfile`" // IG5: generated dependency locks only")
[IO.File]::WriteAllText($ipPath, $ipPatched, [Text.UTF8Encoding]::new($false))
$priorJava = $env:JAVA_HOME
$priorGradleHome = $env:GRADLE_USER_HOME
$priorJavaOptions = $env:JAVA_TOOL_OPTIONS
try {
  $env:JAVA_HOME = $JavaHome
  $env:GRADLE_USER_HOME = Join-Path $BuildRoot 'dependencies\gradle'
  if ($UseWindowsTcpPipe) {
    $shim = & (Join-Path $PSScriptRoot 'build_ghidra_java_tcp.ps1') -JavaHome $JavaHome -BuildRoot (Join-Path $BuildRoot 'build-jdk-tcp-pipe')
    $env:JAVA_TOOL_OPTIONS = ($priorJavaOptions + ' "--patch-module=java.base=' + $shim + '"').Trim()
  }
  $arguments = @('--no-daemon', '--console=plain', "--max-workers=$Workers", '-Dorg.gradle.internal.http.connectionTimeout=15000', '-Dorg.gradle.internal.http.socketTimeout=30000', '-p', $workspace)
  if (!$VsWherePath) {
    $VsWherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (!(Test-Path -LiteralPath $VsWherePath)) {
      $VsWherePath = Join-Path $BuildRoot 'vswhere-3.1.7.exe'
      $vswhereHash = 'c54f3b7c9164ea9a0db8641e81ecdda80c2664ef5a47c4191406f848cc07c662'
      if (!(Test-Path -LiteralPath $VsWherePath)) {
        if ($Offline) { throw 'Offline full Windows build requires vswhere (system installation or pinned maintainer cache)' }
        & curl.exe --fail --location --retry 3 --output $VsWherePath 'https://github.com/microsoft/vswhere/releases/download/3.1.7/vswhere.exe'
        if ($LASTEXITCODE -ne 0) { throw 'Visual Studio discovery acquisition failed' }
      }
      if ((Get-FileHash -LiteralPath $VsWherePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $vswhereHash) { throw 'Pinned vswhere SHA-256 mismatch' }
    }
  }
  $arguments += "-PvswherePath=$([IO.Path]::GetFullPath($VsWherePath))"
  if ($Offline) { $arguments += '--offline' }
  if (!$Offline) {
    & (Join-Path $gradleRoot 'bin\gradle.bat') @arguments '-I' (Join-Path $workspace 'gradle\support\fetchDependencies.gradle') '-DhideDownloadProgress' '-DnoEclipse'
    if ($LASTEXITCODE -ne 0) { throw 'Ghidra pinned build dependency preparation failed' }
  }
  & (Join-Path $gradleRoot 'bin\gradle.bat') @arguments 'buildGhidra' '--write-locks'
  if ($LASTEXITCODE -ne 0) { throw 'Full Ghidra compilation failed; do not label native-only or partial output as a full build' }
  # build/dist also contains separate optional extension archives.
  $distributions = @(Get-ChildItem -LiteralPath (Join-Path $workspace 'build\dist') -Filter '*_win_x86_64.zip' -File | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
  if ($distributions.Count -ne 1) { throw 'Full Ghidra distribution ZIP was not produced' }
  $proof = @{schemaVersion=1; engine='Ghidra'; version='12.1.4'; commit='8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc'; gradleVersion=$gradleVersion; gradleSHA256=$gradleHash; javaHome=$JavaHome; builtUtc=[DateTime]::UtcNow.ToString('o'); sourceRoot=$SourceRoot; windowsBuildTcpPipe=[bool]$UseWindowsTcpPipe; buildWorkspacePatch=@{file='gradle/support/ip.gradle'; scope='Exclude generated gradle.lockfile from upstream IP scan; all actual source/dependency license checks retained'; patchedSHA256=(Get-FileHash -LiteralPath $ipPath -Algorithm SHA256).Hash.ToLowerInvariant()}; fullJavaFrameworkBuilt=$true; artifacts=@($distributions | ForEach-Object { @{path=$_.FullName; bytes=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} }); mobileHostValidated=$false}
  $proof | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $BuildRoot 'build-proof.json') -Encoding utf8
  Write-Output (Join-Path $BuildRoot 'build-proof.json')
} finally {
  $env:JAVA_HOME = $priorJava
  $env:GRADLE_USER_HOME = $priorGradleHome
  $env:JAVA_TOOL_OPTIONS = $priorJavaOptions
}
