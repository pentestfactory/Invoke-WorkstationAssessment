# Invoke-WorkstationAssessment
Security Assessments for Workstations

Run the Invoke-WorkstationAssessment.ps1 in a privileged context
```
powershell -ep bypass
. .\Invoke-WorkstationAssessment.ps1
```

Afterwards you can run the Excel
```
. .\Import-PTFCsvToExcel.ps1
```

If you do not have admin rights yet, use the Invoke-AWPEC.ps1 script. You have to bypass AMSI for PS and .NET as we rely on PowerSharpPack heavily!

````
# BYPASS AMSI PS AND .NET FIRST!
iex(new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/pentestfactory/Invoke-WorkstationAssessment/main/Invoke-AWPEC.ps1')
````
