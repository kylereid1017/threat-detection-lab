# Windows built-in OCR (Windows.Media.Ocr), no downloads. Used by Battery T (PLAN-addendum-T-pagetext.md).
# Input: a text file with one absolute image path per line. Output: JSONL, one {"path","lang","text","error"} per line.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File winocr.ps1 -List paths.txt -Out ocr.jsonl
param([Parameter(Mandatory=$true)][string]$List, [Parameter(Mandatory=$true)][string]$Out)

Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
function Await($op, [Type]$t) {
    $task = $asTaskGeneric.MakeGenericMethod($t).Invoke($null, @($op))
    $task.Wait(-1) | Out-Null
    $task.Result
}
[void][Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
[void][Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
[void][Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics, ContentType = WindowsRuntime]
[void][Windows.Graphics.Imaging.BitmapTransform, Windows.Graphics, ContentType = WindowsRuntime]

$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if ($null -eq $engine) { throw "No OCR language available" }
$maxDim = [Windows.Media.Ocr.OcrEngine]::MaxImageDimension
$lang = $engine.RecognizerLanguage.LanguageTag
$done = @{}
if (Test-Path $Out) {
    foreach ($l in [System.IO.File]::ReadAllLines($Out)) { if ($l) { $done[(ConvertFrom-Json $l).path] = 1 } }
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
$w = New-Object System.IO.StreamWriter($Out, $true, $utf8)
try {
    foreach ($p in [System.IO.File]::ReadAllLines($List)) {
        if (-not $p -or $done.ContainsKey($p)) { continue }
        $rec = [ordered]@{ path = $p; lang = $lang; text = $null; error = $null }
        try {
            $file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($p)) ([Windows.Storage.StorageFile])
            $stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
            $dec = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
            $wpx = $dec.PixelWidth; $hpx = $dec.PixelHeight
            if ($wpx -gt $maxDim -or $hpx -gt $maxDim) {
                # Scale down to fit the engine's limit, keeping the aspect ratio.
                $s = [Math]::Min($maxDim / $wpx, $maxDim / $hpx)
                $tf = New-Object Windows.Graphics.Imaging.BitmapTransform
                $tf.ScaledWidth = [uint32][Math]::Floor($wpx * $s); $tf.ScaledHeight = [uint32][Math]::Floor($hpx * $s)
                $bmp = Await ($dec.GetSoftwareBitmapAsync([Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,
                        [Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied, $tf,
                        [Windows.Graphics.Imaging.ExifOrientationMode]::IgnoreExifOrientation,
                        [Windows.Graphics.Imaging.ColorManagementMode]::DoNotColorManage)) ([Windows.Graphics.Imaging.SoftwareBitmap])
            } else {
                $bmp = Await ($dec.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
            }
            $res = Await ($engine.RecognizeAsync($bmp)) ([Windows.Media.Ocr.OcrResult])
            $rec.text = (($res.Lines | ForEach-Object { $_.Text }) -join "`n")
            $stream.Dispose()
        } catch { $rec.error = $_.Exception.Message }
        $w.WriteLine((ConvertTo-Json $rec -Compress))
        $w.Flush()
    }
} finally { $w.Close() }
