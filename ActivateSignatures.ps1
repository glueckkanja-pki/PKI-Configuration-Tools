$CAName = "CN=COMODO SHA-256 Client Authentication and Secure Email CA, O=COMODO CA Limited, L=Salford, S=Greater Manchester, C=GB"

function CreateOutlookSignatureSettings($OfficeBitness, $SigningCertificate, $EncryptionCertificate, $SettingsName = "Outlook Signature Settings") {

    ## Create detailed Settings

    ### Some preliminary stuff (exact meaning not tested)
    $binPreliminaries = 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00

    ### Settings Name

    $binSettingsNameUnicode = [System.Text.Encoding]::Unicode.GetBytes($SettingsName)
    $binSettingsNameASCII = [System.Text.Encoding]::ASCII.GetBytes($SettingsName)

    [byte[]]$binSettingsName = (0x51,00,($binSettingsNameUnicode.Length+6),00) + $binSettingsNameUnicode + (00, 00)
    $binSettingsName += (0x0b,00,($binSettingsNameASCII.Length+5),00) + $binSettingsNameASCII + (00)

    ### Certificate Hashes

    [byte[]]$BinThumbprintSettings = @()
    if ($null -ne $SigningCertificate) {
        [byte[]]$BinThumbprintSettings += (9,0,0x18,0) + $SigningCertificate.GetCertHash()
    }
    if ($null -ne $EncryptionCertificate) {
        [byte[]]$BinThumbprintSettings += (0x22,0,0x18,0) + $EncryptionCertificate.GetCertHash()
    }

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

function ConfigureOutlookSignatures($OutlookSettingsPath, $OutlookHKLMPath, $SigningCertificate, $EncryptionCertificate) {
    $OfficeBitness = (Get-ItemProperty $OutlookHKLMPath).BitNess
    if ($null -eq $OfficeBitness) {
        Write-Host "Old version of Outlook detected, but it was deinstalled already. This is usually okay." 
        Return 50
    }

    $key = (Get-ItemProperty $OutlookSettingsPath).{11020355}
    if ($null -ne $key) {
        Write-Host "Security Settings already exist." 
        Return 20
    }

    Write-Host "Configuring Outlook in Path $OutlookSettingsPath" 

    [byte[]] $binSettings = CreateOutlookSignatureSettings $OfficeBitness $SigningCertificate $EncryptionCertificate
    $dummy = New-ItemProperty $OutlookSettingsPath -Name 11020355 -PropertyType Binary -Value $binSettings

    [byte]$CryptoEnablerBits = 0
    if ($null -ne $EncryptionCertificate) {
        [byte]$CryptoEnablerBits = $CryptoEnablerBits -bor 0x01 # Bit 0 (LSB) indicates whether encryption is enabled
    }
    if ($null -ne $SigningCertificate) {
        [byte]$CryptoEnablerBits = $CryptoEnablerBits -bor 0x02 # Bit 1 indicates whether signing is enabled
    }

    ## Enable Signatures and/or Encryption as default
    [byte[]]$binCryptoActivation = $CryptoEnablerBits,0,0,0
    $dummy = New-ItemProperty $OutlookSettingsPath -Name 00030354 -PropertyType Binary -Value $binCryptoActivation -Force
}


# Main

## Search for an appropriate certificate
cd cert:\CurrentUser\My
$sOidSecureEmail = "1.3.6.1.5.5.7.3.4"
$cert = (dir | ? { $_.Issuer -eq $CAName -and $_.HasPrivateKey -and $_.Verify() -and ($_.EnhancedKeyUsageList | ? { $_.ObjectId -eq $sOidSecureEmail }) -ne $null })
# REVISIT: If multiple suitable certificates are found, better use the one that expires last

if ($null -eq $cert) {
    Write-Host "No certificate found to be used as signature certificate." 
    Return 30
}

## Configure Outlook 2016 (32 Bit and 64 Bit)
### Either 64 Bit on 64 Bit machine or 32 Bit on 32 Bit machine
if (Test-Path HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook $cert $null
}

### 32 Bit Outlook on 64 Bit Windows
if (Test-Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Outlook $cert $null
}

## Configure Outlook 2013 (32 Bit and 64 Bit)
### Either 64 Bit on 64 Bit machine or 32 Bit on 32 Bit machine
if (Test-Path HKLM:\SOFTWARE\Microsoft\Office\15.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\Microsoft\Office\15.0\Outlook $cert $null
}

### 32 Bit Outlook on 64 Bit Windows
if (Test-Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\15.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\15.0\Outlook $cert $null
}
