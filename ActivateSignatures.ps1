<# 
ActivateSignatures.ps1 Version: 20220407
C. Hannebauer - glueckkanja-gab
T. Kunzi - glueckkanja-gab
F. Schlenz

If found, an email encryption certificate will be configured in Outlook.
This enables the Sign and encrypt buttons of the Options dialogue when composing a message.

	.PARAMETER CAName
    Name of the Issuing CA of the certificate to be used for signing (and encrypting). You must use this exact spacing scheme:
	- No spaces before and after the "=" (except if the actual value contains spaces, naturally)
	- A single space after each comma separating Subject DN components
	
	.SWITCH AlwaysSignMails
    When specified, script will set to always sign the emails as Default

	.SWITCH Force
    When specified script always writes new configuration data, even if some configuration data exist already (for example using an expired certificate or from a previous run of the script)

    .SWITCH EnableEncryption
    When specified, adds the certificate as encryption certificate, too, instead of only signatures.

    .SWITCH AlwaysEncryptMails
    When specified, script will configure that all emails will be encrypted by default 
	
	.EXAMPLE
    .\ActivateSignatures.ps1 -CAName "CN=COMODO RSA Client Authentication and Secure Email CA, O=COMODO CA Limited, L=Salford, S=Greater Manchester, C=GB" -AlwaysSignMails

Changelog:
20170313: Outlook2010, Win2008 EnhancedKeyUsage detection, $AlwaysSignMails, Parameters - T. Kunzi
20170512: Fixed Problems with older Powershell/.NET versions - C. Hannebauer
20170512b: More output (for debugging) - C. Hannebauer
20180104: Force switch and backups - C. Hannebauer
20180104b: Parses existing configuration and overwrites settings if the configured certificate is not valid anymore - C. Hannebauer
20210211: Switch for Encryption Certificate
20220407: Update to allowed algorithms

#>
param
( 
[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='exact name of Issuing CA')][string]$CAName,
[Parameter(Position=1,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='instruct Outlook to sign emails as default setting')][switch]$AlwaysSignMails,
[Parameter(Position=2,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='always write new configuration data, even if some configuration data exists already (for example using an expired certificate)')][switch]$Force,
[Parameter(Position=3,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='adds the certificate as encryption certificate, too, instead of only signatures')][switch]$EnableEncryption,
[Parameter(Position=4,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='instruct Outlook to encrypt emails as default setting')][switch]$AlwaysEncryptMails
)

Class OutlookSignatureSettings {

    [string] $SettingsName;
    [string] $OfficeBitness; # Can only be x86 or x64
    [byte[]] $SigningCertificateHash;
    [byte[]] $EncryptionCertificateHash;

    OutlookSignatureSettings([string] $OfficeBitness, [System.Security.Cryptography.X509Certificates.X509Certificate2] $SigningCertificate, [System.Security.Cryptography.X509Certificates.X509Certificate2] $EncryptionCertificate) {
        
        $this.SettingsName = "Outlook Signature Settings";
        $this.OfficeBitness = $OfficeBitness;
        if ($null -ne $SigningCertificate) {
            $this.SigningCertificateHash = $SigningCertificate.GetCertHash();
        }
        if ($null -ne $EncryptionCertificate) {
            $this.EncryptionCertificateHash = $EncryptionCertificate.GetCertHash();
        }
    }

    OutlookSignatureSettings([string] $OfficeBitness, [byte[]] $binExistingSettings) {
        $this.OfficeBitness = $OfficeBitness

        if ($binExistingSettings.Length -le 20) {
            throw "Existing settings are only $($binExistingSettings.Length) bytes long, too short for real settings.";
        }
        if (($binExistingSettings.Length % 16) -ne 0) {
            throw "Existing settings are $($binExistingSettings.Length) bytes long, which is not dividable by 16. Real settings are always padded to multiples of 16.";
        }

        if (1 -ne ([System.BitConverter]::ToUInt32($binExistingSettings,0))) {
            throw "Existing settings do not start with 01 00 00 00 as expected";
        }
        
        if ($this.OfficeBitness -eq "x86") {
            $lengthOfBody = [System.BitConverter]::ToUInt32($binExistingSettings,4)
            $lengthOfHeader = [System.BitConverter]::ToUInt32($binExistingSettings,8)
            if ($lengthOfHeader -ne 12) {
                throw "Header length encoded to $lengthOfHeader instead of the expected 12";
            }
        }
        ElseIf ($this.OfficeBitness -eq "x64") {
            $lengthOfBody = [System.BitConverter]::ToUInt64($binExistingSettings,4)
            $lengthOfHeader = [System.BitConverter]::ToUInt64($binExistingSettings,12)
            if ($lengthOfHeader -ne 20) {
                throw "Header length encoded to $lengthOfHeader instead of the expected 20";
            }
        }
        Else {
            throw [System.ArgumentException] "Unknown Office Bitness: $this.OfficeBitness"
        }

        $totalLength = $lengthOfBody + $lengthOfHeader;
        $totalLength += (16 - $totalLength % 16)
        if ($totalLength -ne $binExistingSettings.Length) {
            throw "Encoding says the header has a length of $lengthOfHeader bytes, while the body's length should be $lengthOfBody. Together with padding, this should be $totalLength bytes. However, the real length is different, specifically $binExistingSettings.Length bytes.";
        }

        $currentPosition = $lengthOfHeader

        do {
            $packetTag = [BitConverter]::ToUInt16($binExistingSettings, $currentPosition);
            $packetLength = [BitConverter]::ToUInt16($binExistingSettings, $currentPosition + 2);

            switch($packetTag) {
                0x51 {
                    $this.SettingsName = [System.Text.Encoding]::Unicode.GetString($binExistingSettings, $currentPosition + 4, $packetLength - 4);
                }
                0x0b {                    # ASCII name, doesn't need to be parsed
                }
                0x01 {
                    # some value of the preliminaries of unknown purpose
                }
                0x06 {
                    # some value of the preliminaries of unknown purpose
                }
                0x20 {
                    # some value of the preliminaries of unknown purpose
                }
                0x02 {                    # Hash algorithm, doesn't need to be parsed
                }
                0x09 {                    # Signing certificate hash
                    $this.SigningCertificateHash = for($i = 4; $i -lt $packetLength; $i++) { $binExistingSettings[$currentPosition + $i] }
                }
                0x22 {                      # Encryption certificate hash
                    $this.EncryptionCertificateHash = for($i = 4; $i -lt $packetLength; $i++) { $binExistingSettings[$currentPosition + $i] }
                }
                default { Write-Debug "Unknown Packet Tag $packetTag" }
            }

            $currentPosition += $packetLength;
            if ($currentPosition + 4 -gt $binExistingSettings.Length) {
                $packetLength = 0; # Force stop, there is nothing left to read
            }
        } while($packetLength -gt 0) # A packet of length null is actually part of the padding already
    }

    [System.Security.Cryptography.X509Certificates.X509Certificate2] FindSigningCertificate() {
        if ($this.SigningCertificateHash -eq $null) { return $null; }
        
        return dir cert:\CurrentUser\My | ? { @(Compare-Object $_.GetCertHash() $this.SigningCertificateHash -sync 0).Length -eq 0}
    }

    [System.Security.Cryptography.X509Certificates.X509Certificate2] FindEncryptionCertificate() {
    if ($this.EncryptionCertificateHash -eq $null) { return $null; }
        
        return dir cert:\CurrentUser\My | ? { @(Compare-Object $_.GetCertHash() $this.EncryptionCertificateHash -sync 0).Length -eq 0}
    }

    [bool] ValidateSettings() { # Checks whether configured certificates exist and are still valid. If not, return false.

        if ($this.SigningCertificateHash -ne $null) {
            $configuredSigningCertificate = dir cert:\CurrentUser\My | ? { @(Compare-Object $_.GetCertHash() $this.SigningCertificateHash -sync 0).Length -eq 0}
            if ($configuredSigningCertificate -eq $null) {
                Write-Information "Signing Certificate is configured, but does not exist"
                return $false;
            }
            if (-not $configuredSigningCertificate.Verify()) {
                Write-Information "Signing Certificate is configured, but is not valid"
                return $false;
            }
        }

        if ($this.EncryptionCertificateHash -ne $null) {
            $configuredEncryptionCertificate = dir cert:\CurrentUser\My | ? { @(Compare-Object $_.GetCertHash() $this.EncryptionCertificateHash -sync 0).Length -eq 0}
            if ($configuredEncryptionCertificate -eq $null) {
                Write-Information "Encryption Certificate is configured, but does not exist"
                return $false;
            }
            if (-not $configuredEncryptionCertificate.Verify()) {
                Write-Information "Encryption Certificate is configured, but is not valid"
                return $false;
            }
        }

        return $true
    }

    [byte[]] CreateRegistryValue() {

        ## Create detailed Settings
        
        ### Some preliminary stuff (exact meaning not tested)
        [byte[]] $binPreliminaries = 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00

        ### Settings Name

        $binSettingsNameUnicode = [System.Text.Encoding]::Unicode.GetBytes($this.SettingsName)
        $binSettingsNameASCII = [System.Text.Encoding]::ASCII.GetBytes($this.SettingsName)

        [byte[]]$binSettingsName = (0x51,00,($binSettingsNameUnicode.Length+6),00) + $binSettingsNameUnicode + (00, 00)
        $binSettingsName += (0x0b,00,($binSettingsNameASCII.Length+5),00) + $binSettingsNameASCII + (00)

        ### Certificate Hashes

        [byte[]]$BinThumbprintSettings = @()
        if ($null -ne $this.SigningCertificateHash) {
            [byte[]]$BinThumbprintSettings += (9,0,0x18,0) + $this.SigningCertificateHash
        }
        if ($null -ne $this.EncryptionCertificateHash) {
            [byte[]]$BinThumbprintSettings += (0x22,0,0x18,0) + $this.EncryptionCertificateHash
        }

        ### Algorithms
        # SHA-2, AES, 3DES as algorithms, it's ASN.1 encoded from the fifth byte onwards
        [byte[]] $binAlgorithms = 0x02, 0x00, 0x60, 0x00, 0x30, 0x5a, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02

        ### Total

        [byte[]] $binSettingsBody = $binPreliminaries + $binSettingsName + $BinThumbprintSettings + $binAlgorithms
        if ($this.OfficeBitness -eq "x86") {
	        [byte[]] $binSettingsHeader = (1,0,0,0) + [System.BitConverter]::GetBytes($binSettingsBody.Length) + `
		        [System.BitConverter]::GetBytes(12) # Length of the Header in Bytes
        }
        ElseIf ($this.OfficeBitness -eq "x64") {
	        [byte[]] $binSettingsHeader = (1,0,0,0) + [System.BitConverter]::GetBytes($binSettingsBody.LongLength) + `
		        [System.BitConverter]::GetBytes([long]20) # Length of the Header in Bytes
        }
        Else {
            throw [System.ArgumentException] "Unknown Office Bitness: $this.OfficeBitness"
        }

        # Padding to 16 Byte block
        [byte[]] $binSettingsTotal = $binSettingsHeader + $binSettingsBody
        $binSettingsTotal += @(0) * (16 - $binSettingsTotal.Length % 16)

        return $binSettingsTotal
    }
}

function ConfigureOutlookSignatures($OutlookSettingsPath, $OutlookHKLMPath, $SigningCertificate, $EncryptionCertificate) {
    $OfficeBitness = (Get-ItemProperty $OutlookHKLMPath).BitNess
    if ($null -eq $OfficeBitness) {
        Write-Error "Old version of Outlook detected, but it was deinstalled already. This is usually okay." 
        Return 50
    }

    $backupPath = [String]::Empty

    if (Test-Path $OutlookSettingsPath) {
        $key = (Get-ItemProperty $OutlookSettingsPath).{11020355}
        if ($null -ne $key) {
            if ($Force) {
                Write-Information "Security Settings already exist, but continuing due to Force parameter."
            }
            else {
                $binExistingSettings = Get-ItemPropertyValue -Path $OutlookSettingsPath -Name 11020355
                $objExistingSettings = New-Object OutlookSignatureSettings($OfficeBitness, $binExistingSettings)

                if ($objExistingSettings.ValidateSettings()) {
                    Write-Error "Valid Security Settings already exist. Use Force parameter if you still want to write new settings." 
                    Return 20
                }
                else {
                    Write-Information "Security Settings exist already, but they are not valid anymore (an non-existing or expired certificate was configured). Rewriting configuration..."
                }
            }
            
            Write-Information "Creating a backup of the registry key with existing Security Settings now."

            $CurrentDate = Get-Date -Format "s"
            $backupPath = "$OutlookSettingsPath-backups\scriptbackup-$CurrentDate"
            if (-not (Test-Path "$OutlookSettingsPath-backups")) {
                New-Item -Path "$OutlookSettingsPath-backups" -ItemType RegistryKey -Force
            }
            copy $OutlookSettingsPath $backupPath -Force -ErrorAction Stop
        }
    }
    else { # The whole registry key might not exist if Outlook has never touched security settings
        $dummy = New-Item -Path $OutlookSettingsPath -ItemType RegistryKey -Force
    }

    Write-Information "Configuring Outlook in Path $OutlookSettingsPath" 

    try {
        $outlookCertificateConfiguration = new-object OutlookSignatureSettings($OfficeBitness, $SigningCertificate, $EncryptionCertificate)
        [byte[]] $binSettings = $outlookCertificateConfiguration.CreateRegistryValue()
        $dummy = New-ItemProperty $OutlookSettingsPath -Name 11020355 -PropertyType Binary -Value $binSettings -Force:(-not [String]::IsNullOrEmpty($backupPath))

        [byte]$CryptoEnablerBits = 0
        if ($null -ne $EncryptionCertificate) {
            if ($AlwaysEncryptMails) {
		        Write-Debug "AlwaysEncryptMails = true"
                [byte]$CryptoEnablerBits = $CryptoEnablerBits -bor 0x01 # Bit 0 (LSB) indicates whether encryption is enabled
            }
            else
            {
			    Write-Debug "AlwaysEncryptMails = false"
            }
        }
        if ($null -ne $SigningCertificate) {
		    if ($AlwaysSignMails) {
		        Write-Debug "AlwaysSignMails = true"
			    [byte]$CryptoEnablerBits = $CryptoEnablerBits -bor 0x02 # Bit 1 indicates whether signing is enabled
		    }
		    else
		    {
			    Write-Debug "AlwaysSignMails = false"
		    }
        }

        ## Enable Signatures and/or Encryption as default
        [byte[]]$binCryptoActivation = $CryptoEnablerBits,0,0,0
        $dummy = New-ItemProperty $OutlookSettingsPath -Name 00030354 -PropertyType Binary -Value $binCryptoActivation -Force
    }
    catch {
        if ($backupPath -ne [String]::Empty -and (Test-Path $backupPath)) {
            Write-Warning "An error occurred, restoring backup"
            Write-Information "deleting potentially misconfigured registry value"
            del $OutlookSettingsPath
            Write-Information "copying backuped value to the original registry location"
            copy $backupPath $OutlookSettingsPath
        }
        throw
    }
}

# Main
Write-Information "ActivateSignatures Version 20220407"

## Search for an appropriate certificate
$sOidSecureEmail = "1.3.6.1.5.5.7.3.4"
$CandidateCerts = @(dir cert:\CurrentUser\My | ? { $_.Issuer -eq $CAName -and $_.HasPrivateKey -and ( ( ($_.EnhancedKeyUsageList | ? { $_.ObjectId -eq $sOidSecureEmail }) -ne $null) -OR ($_.Extensions| ? {$_.EnhancedKeyUsages | ? {$_.Value -eq $sOidSecureEmail} } ) ) })
Write-Information "There are $($CandidateCerts.Length) certificates for S/MIME"
$ValidCandidateCerts = @($CandidateCerts | ? { $_.Verify() })
Write-Information "Of these S/MIME certificates, $($ValidCandidateCerts.Length) are valid"

# If multiple suitable certificates are found, use the one that expires last
$cert = $ValidCandidateCerts | Sort NotAfter -Descending | Select -First 1

if ($null -eq $cert) {
    Write-Error "No certificate found to be used as signature certificate." 
    Return 30
}

$encryptionCert = $null
if ($EnableEncryption) {
    $encryptionCert = $cert
}

## Configure Outlook 2016 (32 Bit and 64 Bit)
### Either 64 Bit on 64 Bit machine or 32 Bit on 32 Bit machine
if (Test-Path HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook $cert $encryptionCert
}
### 32 Bit Outlook on 64 Bit Windows
if (Test-Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Outlook $cert $encryptionCert
}

## Configure Outlook 2013 (32 Bit and 64 Bit)
### Either 64 Bit on 64 Bit machine or 32 Bit on 32 Bit machine
if (Test-Path HKLM:\SOFTWARE\Microsoft\Office\15.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\Microsoft\Office\15.0\Outlook $cert $encryptionCert
}
### 32 Bit Outlook on 64 Bit Windows
if (Test-Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\15.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook).DefaultProfile

    ConfigureOutlookSignatures "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\15.0\Outlook $cert $encryptionCert
}

## Configure Outlook 2010 (32 Bit and 64 Bit)
### Either 64 Bit on 64 Bit machine or 32 Bit on 32 Bit machine
if (Test-Path HKLM:\SOFTWARE\Microsoft\Office\14.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles").DefaultProfile

    ConfigureOutlookSignatures "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\Microsoft\Office\14.0\Outlook $cert $encryptionCert
}
### 32 Bit Outlook on 64 Bit Windows
if (Test-Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\14.0\Outlook) {
    $DefaultProfile = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles").DefaultProfile

    ConfigureOutlookSignatures "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\$DefaultProfile\c02ebc5353d9cd11975200aa004ae40e" HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\14.0\Outlook $cert $encryptionCert
}
