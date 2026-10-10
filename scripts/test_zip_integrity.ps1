[CmdletBinding()]
param([switch]$KeepFixture)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'runtime_pack.ps1')
. (Join-Path $PSScriptRoot 'bootstrap_distribution.ps1')
Add-Type -AssemblyName System.IO.Compression
$zipTestRoot = Join-Path ([IO.Path]::GetTempPath()) ('ig5-zip-integrity-' + [Guid]::NewGuid().ToString('N'))
$zipCrcSupported = $null -ne [IO.Compression.ZipArchiveEntry].GetProperty('Crc32')

function Check-Integrity { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw "ASSERT: $Message" } }
function Expect-IntegrityFailure { param([scriptblock]$Action,[string]$Expected)
    $failed = $false
    try { & $Action | Out-Null } catch {
        $failed = $true
        Check-Integrity ($_.Exception.Message.Contains($Expected)) "Expected '$Expected': $($_.Exception.Message)"
    }
    Check-Integrity $failed "Expected failure: $Expected"
}
function New-IntegrityZip { param([string]$Path,[string]$Name,[byte[]]$Payload,[switch]$Stored)
    $stream = [IO.File]::Create((ConvertTo-IG5IOPath $Path))
    $archive = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create)
    try {
        $entry = if ($Stored) { $archive.CreateEntry($Name,[IO.Compression.CompressionLevel]::NoCompression) } else { $archive.CreateEntry($Name) }
        $entryStream = $entry.Open()
        try { $entryStream.Write($Payload,0,$Payload.Length) } finally { $entryStream.Dispose() }
    } finally { $archive.Dispose(); $stream.Dispose() }
}

try {
    [IO.Directory]::CreateDirectory((ConvertTo-IG5IOPath $zipTestRoot)) | Out-Null
    Initialize-IG5ZipCrc32
    # Re-importing bootstrap must not redefine an already loaded C# type.
    . (Join-Path $PSScriptRoot 'bootstrap_distribution.ps1')
    Initialize-IG5ZipCrc32
    $vector = [Text.Encoding]::ASCII.GetBytes('123456789')
    $accumulator = [IG5.DistributionIntegrity.V1.Crc32Accumulator]::new()
    $accumulator.Append($vector,4)
    $remainder = New-Object byte[] 5
    [Array]::Copy($vector,4,$remainder,0,5)
    $accumulator.Append($remainder,5)
    Check-Integrity ($accumulator.Value -eq [uint32]3421780262) 'streamed standard CRC32 vector differs'
    $empty = [IG5.DistributionIntegrity.V1.Crc32Accumulator]::new()
    Check-Integrity ($empty.Value -eq 0) 'empty CRC32 must be zero'
    Write-Output 'PASS C# streamed CRC32 vector, chunk accumulation, empty CRC and repeatable dot-source'

    $valid = Join-Path $zipTestRoot 'valid.zip'
    $validDestination = Join-Path $zipTestRoot 'valid-extract'
    New-IntegrityZip $valid 'payload.txt' $vector -Stored
    Expand-IG5VerifiedZip $valid $validDestination
    Check-Integrity ((Read-IG5Text (Join-Path $validDestination 'payload.txt')) -ceq '123456789') 'valid entry changed'
    $emptyZip = Join-Path $zipTestRoot 'empty.zip'
    $emptyDestination = Join-Path $zipTestRoot 'empty-extract'
    New-IntegrityZip $emptyZip 'empty.txt' (New-Object byte[] 0) -Stored
    Expand-IG5VerifiedZip $emptyZip $emptyDestination
    Check-Integrity ((New-Object IO.FileInfo (Join-Path $emptyDestination 'empty.txt')).Length -eq 0) 'empty ZIP entry changed'
    Write-Output 'PASS valid stored data and empty entry extract unchanged'

    if ($zipCrcSupported) {
        $corrupt = Join-Path $zipTestRoot 'same-length-corrupt.zip'
        $data = [IO.File]::ReadAllBytes($valid)
        Check-Integrity ([BitConverter]::ToUInt32($data,0) -eq 0x04034b50) 'stored local header missing'
        Check-Integrity ([BitConverter]::ToUInt16($data,8) -eq 0) 'corruption fixture must be stored, not compressed'
        $dataAt = 30 + [BitConverter]::ToUInt16($data,26) + [BitConverter]::ToUInt16($data,28)
        $data[$dataAt] = $data[$dataAt] -bxor 1
        [IO.File]::WriteAllBytes($corrupt,$data)
        Expect-IntegrityFailure { Expand-IG5VerifiedZip $corrupt (Join-Path $zipTestRoot 'corrupt-extract') } 'ZIP entry integrity mismatch'
        Write-Output 'PASS same-length corruption is rejected by the public entry CRC'
    } else {
        Write-Output 'INFO Public ZipArchiveEntry.Crc32 is unavailable: same-length CRC rejection is not claimed; pinned ZIP SHA-256 and file inventory checks remain mandatory.'
    }

    $forged = Join-Path $zipTestRoot 'forged-length.zip'
    New-IntegrityZip $forged 'forged.txt' ([Text.Encoding]::ASCII.GetBytes(('A'*65536)))
    $data = [IO.File]::ReadAllBytes($forged)
    $central = -1
    for ($index = 0; $index -lt $data.Length - 28; $index++) {
        if ([BitConverter]::ToUInt32($data,$index) -eq 0x02014b50) { $central = $index; break }
    }
    Check-Integrity ($central -ge 0) 'fixture central directory missing'
    [BitConverter]::GetBytes([uint32]1).CopyTo($data,$central+24)
    [IO.File]::WriteAllBytes($forged,$data)
    $forgedDestination = Join-Path $zipTestRoot 'forged-extract'
    $expected = if ($zipCrcSupported) { 'ZIP entry integrity mismatch' } else { 'ZIP expanded byte/time budget exceeded' }
    Expect-IntegrityFailure { Expand-IG5VerifiedZip $forged $forgedDestination } $expected
    Check-Integrity ((New-Object IO.FileInfo (Join-Path $forgedDestination 'forged.txt')).Length -le 1) 'forged length wrote excess expanded bytes'
    Write-Output 'PASS forged central length fails without writing excess expanded bytes'

    $unsafe = Join-Path $zipTestRoot 'unsafe.zip'
    $unsafeDestination = Join-Path $zipTestRoot 'unsafe-extract'
    New-IntegrityZip $unsafe '../outside.txt' $vector
    Expect-IntegrityFailure { Expand-IG5VerifiedZip $unsafe $unsafeDestination } 'Unsafe ZIP path'
    Check-Integrity (-not (Test-IG5Path $unsafeDestination)) 'unsafe ZIP wrote a destination before path validation'
    Write-Output 'PASS unsafe paths still fail before extraction'
    Write-Output ("IG5 ZIP integrity fixtures passed: PowerShell={0}; CLR={1}; publicCrc32={2}; no profile or engine accessed." -f $PSVersionTable.PSVersion,[Environment]::Version,$zipCrcSupported)
} finally {
    if ($KeepFixture) { Write-Output "FIXTURE_ROOT=$zipTestRoot" }
    elseif (Test-IG5Path $zipTestRoot) {
        $safe = Get-IG5FullPath $zipTestRoot
        $boundary = (Get-IG5FullPath ([IO.Path]::GetTempPath())).TrimEnd('\') + '\'
        if (-not $safe.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $safe -Leaf) -notmatch '^ig5-zip-integrity-[a-f0-9]{32}$') { throw 'Unsafe ZIP fixture cleanup path' }
        Assert-IG5NoReparsePath $safe
        Remove-IG5Tree $safe
    }
}
