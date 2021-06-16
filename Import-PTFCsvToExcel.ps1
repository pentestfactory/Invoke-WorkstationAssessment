﻿
### Create a new Excel Workbook with one empty sheet
$excel = New-Object -ComObject excel.application 
$outputXLSX = "C:\Users\Administrator\Desktop\$(get-date -f yyyyMMdd)_Workstation_Hardening_Assessment.xlsx"
$csvsPath = "C:\Users\Administrator\Desktop\CSV\"
$csvs = Get-ChildItem "$($csvsPath)*.csv"

$excel.SheetsInNewWorkbook = $csvs.Count
$Workbook = $excel.Workbooks.Add()
$sheet = 1

# Image
# Image format and properties
# $path = "C:\ptflogo.jpg"
# $base64ptf = [convert]::ToBase64String((Get-Content $path -Encoding byte))

$base64ptf = "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"
$bytes = [System.Convert]::FromBase64String($base64ptf)
Remove-Variable base64ptf

$CompanyLogo = "$($csvsPath)'SOS_Logo.jpg')"
$p = New-Object IO.MemoryStream($bytes, 0, $bytes.length)
$p.Write($bytes, 0, $bytes.length)
Add-Type -AssemblyName System.Drawing
$picture = [System.Drawing.Image]::FromStream($p, $true)
$picture.Save($CompanyLogo)

Remove-Variable bytes
Remove-Variable p
Remove-Variable picture

$LinkToFile = $false
$SaveWithDocument = $true
$Left = 20
$Top = 10
$Width = 383 / 8
$Height = 403 / 8

Write-Host "Detected the following CSV files: $($csvs.Count)"


foreach ($csv in $csvs)
{
    $worksheet = $workbook.worksheets.Item($sheet)
    $worksheet.Shapes.AddPicture($CompanyLogo, $LinkToFile, $SaveWithDocument, $Left, $Top, $Width, $Height) | Out-Null
    $inputCSV = "$($csvsPath)$($csv.Name)"
    #  Write-Host $inputCSV

    ### Build the QueryTables.Add command
    ### QueryTables does the same as when clicking "Data » From Text" in Excel
    $TxtConnector = ("TEXT;" + $inputCSV)
    $Connector = $worksheet.QueryTables.add($TxtConnector,$worksheet.Range("A6"))
    $query = $worksheet.QueryTables.item($Connector.name)

    ### Set the delimiter (, or ;) according to your regional settings
    $query.TextFileOtherDelimiter = $Excel.Application.International(5)

    ### Set the format to delimited and text for every column
    ### A trick to create an array of 2s is used with the preceding comma
    $query.TextFileParseType  = 1
    $query.TextFileColumnDataTypes = ,2 * $worksheet.Cells.Columns.Count
    $query.AdjustColumnWidth = 1

    ### Execute & delete the import query
    $query.Refresh()
    $query.Delete()

    $listObject = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $worksheet.UsedRange, $null, [Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes, $null)
    $listObject.TableStyle = "TableStyleMedium19" # Style Cheat Sheet: https://msdn.microsoft.com/en-au/library/documentformat.openxml.spreadsheet.tablestyle.aspx
    $worksheet.UsedRange.EntireColumn.AutoFit() | Out-Null
    $worksheet.Name = [io.path]::GetFileNameWithoutExtension("$inputCSV")

    # Title of worksheet
    $row = 3
    $column = 1
    $worksheet.Cells.Item($row,$column)= "                         $([io.path]::GetFileNameWithoutExtension("$inputCSV"))"
    $worksheet.Cells.Item($row,$column).Style = "Accent4"
    $worksheet.Cells.Item($row,$column).Font.Size = 15
    $worksheet.Columns.Item(1).columnWidth = 50

    $sheet++
}


### Save & close the Workbook as XLSX. Change the output extension for Excel 2003
$Workbook.SaveAs($outputXLSX,51)
$excel.Quit()