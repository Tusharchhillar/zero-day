$ErrorActionPreference = 'Stop'
$Error.Clear()
$ppt = $null
try {
    $ppt = New-Object -ComObject PowerPoint.Application
    $pres = $ppt.Presentations.Open('C:\Users\chhil\AppData\Local\Temp\zdpdf\zero-day.pptx', $true, $false, $false)
    Write-Output "OPENED"
    # ppSaveAsPDF = 32
    $pres.SaveAs('C:\Users\chhil\AppData\Local\Temp\zdpdf\zero-day.pdf', 32)
    Write-Output "SAVED"
    $pres.Close()
    $ppt.Quit()
    Write-Output "PDF-EXPORT-DONE"
} catch {
    Write-Output ("ERROR: " + $_.Exception.Message)
    Write-Output ("TYPE: " + $_.Exception.GetType().FullName)
    if ($ppt) { try { $ppt.Quit() } catch {} }
    exit 1
}