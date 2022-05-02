<# 
Export-SMIMECertificate.ps1 Version: 20220502
C. Hannebauer - glueckkanja-gab

Searches for S/MIME encryption certificates in the user store. All found certificates will be exported to PFX files.
	.PARAMETER Path
    Where to export the certificates to, e.g. "%OneDriveCommercial%\smimecerts.pfx"
	.PARAMETER Password
    The password with which the exported PFX files will be protected.	
	
	.EXAMPLE
    .\Export-SMIMECertificate.ps1 -Path "%OneDriveCommercial%\smimecerts.pfx" -Password "password" -CAName "CN=COMODO RSA Client Authentication and Secure Email CA, O=COMODO CA Limited, L=Salford, S=Greater Manchester, C=GB"
#>
param
( 
[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='the file path to export the certificates to')][string]$Path,
[Parameter(Position=1,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='the password with which the exported PFX files will be protected')][string]$Password
)

## Search for S/MIME certificates
$sOidSecureEmail = "1.3.6.1.5.5.7.3.4"
$CandidateCerts = @(Get-ChildItem cert:\CurrentUser\My -EKU $sOidSecureEmail) | Where-Object { $_.HasPrivateKey }
Write-Information "There are $($CandidateCerts.Length) certificates for S/MIME"

$sOidKeyUsageExtension = "2.5.29.15"
$encryptionCertificates = $CandidateCerts | Where-Object { ($null -eq ($_.Extensions | Where-Object { $_.Oid -eq $sOidKeyUsageExtension })) -OR ($null -ne ($_.Extensions | Where-Object { $_.Oid -eq $sOidKeyUsageExtension -AND $_.KeyUsages.HasFlag([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment)})) }

$certs4export = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$certs4export.AddRange($encryptionCertificates)
$baPFX = $certs4export.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $Password)

$expandedPath = [System.Environment]::ExpandEnvironmentVariables($Path)
[System.IO.File]::WriteAllBytes($expandedPath, $baPFX)
