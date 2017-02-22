$CAName = "CN=COMODO SHA-256 Client Authentication and Secure Email CA, O=COMODO CA Limited, L=Salford, S=Greater Manchester, C=GB"

cd cert:\CurrentUser\My
$cert = (dir | ? { $_.Issuer -eq $CAName -and $_.HasPrivateKey -and $_.Verify() -and ($_.EnhancedKeyUsageList | ? { $_.ObjectId -eq "1.3.6.1.5.5.7.3.4" }) -ne $null }) # 1.3.6.1.5.5.7.3.4 is the OID of Secure Email

if ($null -eq $cert) {
    Write-Host "No certificate found to be used as signature certificate." 
    Return 30
}

function CreateOutlookSignatureSettings($OfficeBitness) {

    ## Create detailed Settings

    ### Some preliminary stuff (exact meaning not tested)
    $binPreliminaries = 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00

    ### Settings Name
    $SettingsName = "Outlook Signature Settings"

    $binSettingsNameUnicode = [System.Text.Encoding]::Unicode.GetBytes($SettingsName)
    $binSettingsNameASCII = [System.Text.Encoding]::ASCII.GetBytes($SettingsName)

    [byte[]]$binSettingsName = (0x51,00,($binSettingsNameUnicode.Length+6),00) + $binSettingsNameUnicode + (00, 00)
    $binSettingsName += (0x0b,00,($binSettingsNameASCII.Length+5),00) + $binSettingsNameASCII + (00)

    ### Certificate Hashes

    [byte[]]$BinThumbprintSettings = (9,0,0x18,0) + $cert.GetCertHash() # Signature certificate
    # (0x22,0,0x18,0) + $cert.GetCertHash() # Encryption Certificate

    ### Algorithms
    # Sha256 as Hash algorithm, it's ASN.1 encoded
    [byte[]] $binAlgorithms = 0x02, 0x00, 0x36, 0x00, 0x30, 0x30, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x30, 0x07, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A

    ### Total

    [byte[]] $binSettingsBody = $binPreliminaries + $binSettingsName + $BinThumbprintSettings + $binAlgorithms
    if ($OfficeBitness -eq "x86") {
	    [byte[]] $binSettingsHeader = (1,0,0,0) + [System.BitConverter]::GetBytes($binSettingsBody.Length) + `
		    [System.BitConverter]::GetBytes(12) # Length of the Header in Bytes
    }
    ElseIf ($OfficeBitness -eq "x64") {
	    [byte[]] $binSettingsHeader = (1,0,0,0) + [System.BitConverter]::GetBytes($binSettingsBody.LongLength) + `
		    [System.BitConverter]::GetBytes([long]20) # Length of the Header in Bytes
    }
    Else {
        throw [System.ArgumentException] "Unknown Office Bitness: $OfficeBitness"
    }

    # Padding to 16 Byte block
    [byte[]] $binSettingsTotal = $binSettingsHeader + $binSettingsBody
    $binSettingsTotal += @(0) * (16 - $binSettingsTotal.Length % 16)

    return $binSettingsTotal
}

function ConfigureOutlookSignatures($OutlookSettingsPath, $OutlookHKLMPath) {
    $OfficeBitness = (Get-ItemProperty $OutlookHKLMPath).BitNess
    if ($null -eq $OfficeBitness) {
        Write-Host "Old version of Outlook detected, but it was deinstalled already. This is usually okay." 
        Return 50
    }

    $key = (Get-ItemProperty $OutlookSettingsPath).{00030354}
    if ($null -ne $key) {
        Write-Host "Security Settings already exist." 
        Return 20
    }

    Write-Host "Configuring Outlook in Path $OutlookSettingsPath" 

    [byte[]] $binSettings = CreateOutlookSignatureSettings $OfficeBitness
    $dummy = New-ItemProperty $OutlookSettingsPath -Name 11020355 -PropertyType Binary -Value $binSettings

    ## Enable Signatures
    [byte[]]$binCryptoActivation = 2,0,0,0   # Signature enabled (2), Encryption disabled (not 1)
    $dummy = New-ItemProperty $OutlookSettingsPath -Name 00030354 -PropertyType Binary -Value $binCryptoActivation
}

if (Test-Path HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook
}

if (Test-Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Outlook
}

if (Test-Path HKLM:\SOFTWARE\Microsoft\Office\15.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\Microsoft\Office\15.0\Outlook
}

if (Test-Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\15.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\15.0\Outlook
}
