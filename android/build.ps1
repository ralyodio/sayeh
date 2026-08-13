<#
    Sayeh - Android build without Gradle.

    Everything the app needs is in the platform framework (android.*, java.*,
    javax.crypto.*), so there is nothing to resolve from Maven and no Gradle
    daemon to feed. This drives the SDK tools directly:

        aapt2 compile -> aapt2 link -> javac -> d8 -> zip -> zipalign -> apksigner

    Usage:
        .\build.ps1                 build a signed APK
        .\build.ps1 -Install        build, then install on a connected device
        .\build.ps1 -Clean          wipe intermediates first
#>

[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Clean,
    [string]$Serial,
    [string]$Sdk = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$BuildToolsVersion = "35.0.0",
    [string]$Platform = "android-35",
    [int]$MinSdk = 26,
    [int]$TargetSdk = 35
)

$ErrorActionPreference = "Stop"

$ProjectDir = $PSScriptRoot
$RootDir    = Split-Path $ProjectDir -Parent
$BuildDir   = Join-Path $RootDir "build\android"
$OutApk     = Join-Path $RootDir "build\Sayeh.apk"

$BuildTools = Join-Path $Sdk "build-tools\$BuildToolsVersion"
$AndroidJar = Join-Path $Sdk "platforms\$Platform\android.jar"

$Aapt2     = Join-Path $BuildTools "aapt2.exe"
$D8        = Join-Path $BuildTools "d8.bat"
$ZipAlign  = Join-Path $BuildTools "zipalign.exe"
$ApkSigner = Join-Path $BuildTools "apksigner.bat"

$Keystore     = Join-Path $ProjectDir "keystore\sayeh.jks"
$KeystorePass = "sayeh-keystore" # keytool requires at least 6 characters
$KeyAlias     = "sayeh"

function Step($n, $text) { Write-Host "[$n/8] $text" -ForegroundColor Cyan }

function Ensure($path, $what) {
    if (-not (Test-Path $path)) { throw "$what not found: $path" }
}

# Native tools routinely write progress to stderr (keytool -v and apksigner
# both do). Under $ErrorActionPreference = "Stop" PowerShell turns that into a
# terminating NativeCommandError even on a clean exit, so run them with the
# preference relaxed and judge them by their exit code instead.
function Invoke-Tool {
    param([string]$What, [scriptblock]$Command)

    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Command } finally { $ErrorActionPreference = $previous }

    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit code $LASTEXITCODE)" }
}

Ensure $Aapt2 "aapt2"
Ensure $D8 "d8"
Ensure $ZipAlign "zipalign"
Ensure $ApkSigner "apksigner"
Ensure $AndroidJar "android.jar ($Platform)"

if ($Clean -and (Test-Path $BuildDir)) { Remove-Item $BuildDir -Recurse -Force }

$GenDir     = Join-Path $BuildDir "gen"
$ClassesDir = Join-Path $BuildDir "classes"
$DexDir     = Join-Path $BuildDir "dex"
$ResZip     = Join-Path $BuildDir "res.zip"
$BaseApk    = Join-Path $BuildDir "base.apk"
$AlignedApk = Join-Path $BuildDir "aligned.apk"
$ClassesJar = Join-Path $BuildDir "classes.jar"

foreach ($d in $BuildDir, $GenDir, $ClassesDir, $DexDir) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

# ---------------------------------------------------------------------------
Step 1 "Compiling resources"
Invoke-Tool "aapt2 compile" {
    & $Aapt2 compile --dir (Join-Path $ProjectDir "res") -o $ResZip
}

# ---------------------------------------------------------------------------
Step 2 "Linking resources and generating R.java"
Invoke-Tool "aapt2 link" {
    & $Aapt2 link `
        -o $BaseApk `
        -I $AndroidJar `
        --manifest (Join-Path $ProjectDir "AndroidManifest.xml") `
        --java $GenDir `
        --min-sdk-version $MinSdk `
        --target-sdk-version $TargetSdk `
        --version-code 3 `
        --version-name "3.0" `
        $ResZip
}

# ---------------------------------------------------------------------------
Step 3 "Compiling Java sources"
# SelfTest is a desktop verification harness; it has no business in the APK.
$sources = @()
$sources += Get-ChildItem (Join-Path $ProjectDir "java") -Recurse -Filter *.java |
            Where-Object { $_.Name -ne "SelfTest.java" } |
            Select-Object -ExpandProperty FullName
$sources += Get-ChildItem $GenDir -Recurse -Filter R.java | Select-Object -ExpandProperty FullName

Invoke-Tool "javac" {
    & javac -encoding UTF-8 -source 17 -target 17 -nowarn `
        -classpath $AndroidJar -d $ClassesDir $sources
}

# ---------------------------------------------------------------------------
Step 4 "Packing classes into a jar"
Invoke-Tool "jar" { & jar --create --file $ClassesJar -C $ClassesDir . }

# ---------------------------------------------------------------------------
Step 5 "Translating to Dalvik bytecode (d8)"
Invoke-Tool "d8" {
    & $D8 --release --min-api $MinSdk --lib $AndroidJar --output $DexDir $ClassesJar
}

# ---------------------------------------------------------------------------
Step 6 "Adding classes.dex to the package"
# Both assemblies are needed on Windows PowerShell 5.1: ZipFile lives in
# ...Compression.FileSystem, ZipArchiveMode in ...Compression.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$zip = [System.IO.Compression.ZipFile]::Open($BaseApk, [System.IO.Compression.ZipArchiveMode]::Update)
try {
    foreach ($dex in Get-ChildItem $DexDir -Filter *.dex) {
        $existing = $zip.GetEntry($dex.Name)
        if ($existing) { $existing.Delete() }
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $zip, $dex.FullName, $dex.Name,
            [System.IO.Compression.CompressionLevel]::Optimal)
    }
} finally {
    $zip.Dispose()
}

# ---------------------------------------------------------------------------
Step 7 "Aligning"
# resources.arsc must stay uncompressed and 4-byte aligned for targetSdk >= 30.
if (Test-Path $AlignedApk) { Remove-Item $AlignedApk -Force }
Invoke-Tool "zipalign" { & $ZipAlign -f -p 4 $BaseApk $AlignedApk }
Invoke-Tool "zipalign -c" { & $ZipAlign -c -p 4 $AlignedApk }

# ---------------------------------------------------------------------------
Step 8 "Signing"
if (-not (Test-Path $Keystore)) {
    Write-Host "      creating a self-signed key (first run only)" -ForegroundColor DarkGray
    New-Item -ItemType Directory -Force -Path (Split-Path $Keystore -Parent) | Out-Null
    Invoke-Tool "keytool" {
        & keytool -genkeypair `
            -keystore $Keystore -storetype PKCS12 `
            -storepass $KeystorePass -keypass $KeystorePass `
            -alias $KeyAlias -keyalg RSA -keysize 4096 -validity 10000 `
            -dname "CN=Sayeh, OU=Sayeh, O=Sayeh, C=IR"
    }
}

if (Test-Path $OutApk) { Remove-Item $OutApk -Force }
Invoke-Tool "apksigner sign" {
    & $ApkSigner sign `
        --ks $Keystore --ks-pass "pass:$KeystorePass" --key-pass "pass:$KeystorePass" `
        --ks-key-alias $KeyAlias `
        --min-sdk-version $MinSdk `
        --out $OutApk $AlignedApk
}
Invoke-Tool "apksigner verify" {
    & $ApkSigner verify --min-sdk-version $MinSdk --verbose $OutApk
}

$size = [math]::Round((Get-Item $OutApk).Length / 1KB, 1)
Write-Host ""
Write-Host "APK ready: $OutApk  ($size KB)" -ForegroundColor Green

if ($Install) {
    $adb = Join-Path $Sdk "platform-tools\adb.exe"
    Ensure $adb "adb"
    $target = if ($Serial) { @("-s", $Serial) } else { @() }
    Invoke-Tool "adb install" { & $adb @target install -r --no-incremental $OutApk }
}
