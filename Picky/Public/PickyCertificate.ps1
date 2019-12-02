. "$PSScriptRoot/../Private/PickyConfig.ps1"
. "$PSScriptRoot/../Private/RSAHelper.ps1"
. "$PSScriptRoot/../Private/FileHelper.ps1"
. "$PSScriptRoot/../Private/PlatformHelper.ps1"

function Request-Certificate(
    [Parameter(Mandatory=$true, HelpMessage="Picky Server URL")]
    [string]$Subject,
    [Parameter(Mandatory=$true)]
    [string]$PickyApiKey,
    [Parameter(Mandatory=$true, HelpMessage="Picky Server URL")]
    [string]$PickyUrl
){
    $contentsDen = Invoke-RestMethod -Uri "$PickyUrl/chain" -Method 'GET' -ContentType 'text/plain'
    $ca_chain_from_den = @()
    $contentsDen | Select-String  -Pattern '(?smi)^-{2,}BEGIN CERTIFICATE-{2,}.*?-{2,}END CERTIFICATE-{2,}' `
    			-Allmatches | ForEach-Object {$_.Matches} | ForEach-Object { $ca_chain_from_den += $_.Value }

    if(!($ca_chain_from_den.Count -eq 2)){
        throw "Unexpected CA Chain"
    }

    $key_size = 2048
    $subject = "CN=${Subject}"
    $rsa_key = [System.Security.Cryptography.RSA]::Create($key_size)
    $certRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $subject, $rsa_key,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    $csr_der = $certRequest.CreateSigningRequest()

    $headers = @{
        "Authorization" = "Bearer $PickyApiKey"
        "Content-Transfer-Encoding" = "binary"
        "Content-Disposition" = "attachment"
    }

    $certificate = Invoke-RestMethod -Uri $PickyUrl/signcert/ -Method 'POST' `
        -ContentType 'application/pkcs10' `
        -Headers $headers `
        -Body $csr_der

    if($certificate){
        $guid = [System.Guid]::NewGuid();
        $picky_certificate_path = Get-PickyConfig
        $sb = [System.Text.StringBuilder]::new()
        $csr_base64 = [Convert]::ToBase64String($csr_der)
    
        $offset = 0
        $line_length = 64
    
        [void]$sb.AppendLine("-----BEGIN CERTIFICATE REQUEST-----")
        while ($offset -lt $csr_base64.Length) {
            $line_end = [Math]::Min($offset + $line_length, $csr_base64.Length)
            [void]$sb.AppendLine($csr_base64.Substring($offset, $line_end - $offset))
        $offset = $line_end
        }
    
        [void]$sb.AppendLine("-----END CERTIFICATE REQUEST-----")
    
        $csr_pem = $sb.ToString()
    
        $RSAParams = $rsa_key.ExportParameters($true);
        $privateKey = ExportPrivateKeyFromRSA $RSAParams
        $privateKey = $privateKey -Replace "`r`n", "`n"
    
        $certificate_path = "$picky_certificate_path/$guid.pem"
        Add-PathIfNotExist $certificate_path
        $certificate_path = Resolve-Path -Path $certificate_path

        $private_key_path = "$picky_certificate_path/$guid.key"
        Add-PathIfNotExist $private_key_path
        $private_key_path = Resolve-Path -Path $private_key_path

        $csr_pem_path = "$picky_certificate_path/$guid.csr"
        Add-PathIfNotExist $csr_pem_path
        $csr_pem_path = Resolve-Path -Path $csr_pem_path

        $Utf8NoBomEncoding = [System.Text.UTF8Encoding]::new($False)

        $certificate = $certificate + $ca_chain_from_den[0]

        [System.IO.File]::WriteAllLines($csr_pem_path, $csr_pem, $Utf8NoBomEncoding)
        [System.IO.File]::WriteAllLines($private_key_path, $privateKey, $Utf8NoBomEncoding)
        [System.IO.File]::WriteAllLines($certificate_path, $certificate, $Utf8NoBomEncoding)

        Write-Host "$picky_certificate_path/$guid.pem"
    }
}

function Save-CertificateOnServer(
    [Parameter(Mandatory=$true)]
    [string]$PickyApiKey,
    [Parameter(Mandatory=$true)]
    [string]$CertificateID,
    [Parameter(Mandatory=$true, HelpMessage="Picky Server URL")]
    [string]$PickyUrl
){
    $picky_certificate_path = Get-PickyConfig

    $certificate = Get-Content -Path "$picky_certificate_path/$CertificateID.pem" -Raw
    $certificate = $certificate -Replace "`r`n", "`n"

    $headers = @{
        "Authorization" = "Bearer $PickyApiKey"
    }

    $json = @{
        "certificate" = $certificate
    } | ConvertTo-Json

    Invoke-RestMethod -Uri $PickyUrl/cert/ -Method 'POST' `
        -ContentType 'application/json' `
        -Headers $headers `
        -Body $json
}

function Remove-LocalCertificate(
    [Parameter(Mandatory=$true)]
    [string]$CertificateID
){
    $picky_certificate_path = Get-PickyConfig
    
    Remove-Item -Path "$picky_certificate_path/$CertificateID.key" -Force
    Remove-Item -Path "$picky_certificate_path/$CertificateID.pem" -Force
    Remove-Item -Path "$picky_certificate_path/$CertificateID.csr" -Force
}

function Get-LocalCertificates(){
    $picky_certificate_path = Get-PickyConfig
    $ListItem = Get-ChildItem -Path $picky_certificate_path

    $certificateRegex = '[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}.pem'
    $certificate_list = New-Object System.Collections.ArrayList

    foreach($item in $ListItem){
        if($item -CMatch $certificateRegex){
            $content = Get-Content -Path $item -Raw
            $item_guid = ($item.Name -Replace $item.Extension, "")

            if(!($content)){
                Remove-Certificate $item_guid
            }

            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate]::new($item)
            $temp = New-Object System.Object
            $temp | Add-Member -MemberType NoteProperty -Name "Issuer" -Value $certificate.Issuer
            $temp | Add-Member -MemberType NoteProperty -Name "Subject" -Value $certificate.Subject
            $temp | Add-Member -MemberType NoteProperty -Name "ID" -Value $item_guid
            $certificate_list.Add($temp) | Out-Null

            continue;
        }
    }

    Write-Host ($certificate_list | Format-Table | Out-String)
}

Function Save-RootCaCertificate(
    [Parameter(Mandatory=$true, HelpMessage="Picky Server URL")]
    [string]$PickyUrl
){
    $contentsDen = Invoke-RestMethod -Uri "$PickyUrl/chain" -Method 'GET' -ContentType 'text/plain'
    $ca_chain_from_den = @()
    $contentsDen | Select-String  -Pattern '(?smi)^-{2,}BEGIN CERTIFICATE-{2,}.*?-{2,}END CERTIFICATE-{2,}' `
    			-Allmatches | ForEach-Object {$_.Matches} | ForEach-Object { $ca_chain_from_den += $_.Value }

    if(!($ca_chain_from_den.Count -eq 2)){
      throw "Unexpected CA Chain"
    }

    $tempDirectory = New-TemporaryDirectory
    $DenRootCa = "$tempDirectory/root_ca.pem"
    $Utf8NoBomEncoding = [System.Text.UTF8Encoding]::new($False)
    [System.IO.File]::WriteAllLines($DenRootCa, $ca_chain_from_den[1], $Utf8NoBomEncoding)

    Write-Host $DenRootCa
}

function Install-TrustStoreCertificate(
    [Parameter(Mandatory=$true)]
    [string] $RootCertificatePath
){
    $RootCertificatePath = Resolve-Path -Path $RootCertificatePath
    $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($RootCertificatePath)

    if(Get-IsWindows){
        if(!(Get-IsRunAsAdministrator)){
            throw "You need to run as administrator to call this function"
        }
        
        #Trust Store Windows
        $OpenFlags = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite
        $StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        $StoreName = [System.Security.Cryptography.X509Certificates.StoreName]::Root
        $Store = new-object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
        $Store.Open($OpenFlags)
        $Store.Add($Cert)
        $Store.Close()

        #Change the firefox settings to get the certificate from Store
        try{
          $firefoxPath = Resolve-Path "C:\Program Files\Mozilla Firefox\defaults\pref"
        }
        catch{
          Write-Warning "Firefox is not installed, if you install Firefox, please start again this command"
          return;
        }
    }
    if($IsMacOS){
        #Trust Store MacOS
        & sudo security add-trusted-cert -d -k /Library/Keychains/System.keychain $RootCertificatePath

        #Change the firefox settings to get the certificate from Store
        try{
          $firefoxPath = Resolve-Path "/Applications/Firefox.app/Contents/Resources/defaults/pref"
        }
        catch{
          Write-Warning "Firefox is not installed, if you install Firefox, please start again this command"
          return;
        }         
    }

    #Trust Store Firefox for Windows and Macos
    if(!$IsLinux){
        try{
            $name = "firefox-truststore.js"
            $_ = New-Item -ItemType File -Path (Join-Path $firefoxPath $name)
            $ToWrite = "pref(`"security.enterprise_roots.enabled`", true);"
            $AsciiEncoding = [System.Text.ASCIIEncoding]::new()
            [System.IO.File]::WriteAllLines((Join-Path $firefoxPath $name), $ToWrite, $AsciiEncoding)
        }
        catch{
          Write-Warning "Firefox is not installed, if you install Firefox, please start again this command"
        }
    }

    if($IsLinux){
        #Trust Store Chrome
        try{
          certutil
        }
        catch{
          Write-Host "Install libnss3 to manage root certificate" -ForegroundColor Blue
          sudo apt-get install libnss3-tools
        }

        $PkiName = $Cert.Subject.Replace("CN=", "")

        if(Test-Path "$HOME/.pki/"){
          Write-Host "Install Root CA for Chrome" -ForegroundColor Green
          certutil -d sql:$HOME/.pki/nssdb -A -t "CT,C,C" -n "$($PkiName)" -i $RootCertificatePath
        }

        #Trust Store Firefox
        $ListItem = Get-ChildItem -Path $HOME/.mozilla/firefox/
        $firefoxRegex = '[a-z0-9]{8}.default'

        foreach($item in $ListItem){
            if($item -CMatch $firefoxRegex){
                Write-Host "Install Root CA for Firefox" -ForegroundColor Green
                certutil -d sql:$item/ -A -t "CT,C,C" -n "$($PkiName)" -i $RootCertificatePath
                break;
            }
        }
    }
}

Function Remove-TrustStoreCertificate(
    [Parameter(Mandatory=$true)]
    [string] $RootCertificatePath
){
    $RootCertificatePath = Resolve-Path -Path $RootCertificatePath
    $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($RootCertificatePath)
    $PkiName = $Cert.Subject.Replace("CN=", "")

    if(Get-IsWindows){
        if(!(Get-IsRunAsAdministrator)){
            throw "You need to run as administrator to call this function"
        }
        
        #Trust Store Windows
        $OpenFlags = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite
        $StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        $StoreName = [System.Security.Cryptography.X509Certificates.StoreName]::Root
        $Store = new-object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
        $Store.Open($OpenFlags)
        $Store.Remove($Cert)
        $Store.Close()
    }

    if($IsMacOS){
        #Trust Store MacOS
        & sudo security delete-certificate -c $PkiName /Library/Keychains/System.keychain
    }

    if($IsLinux){
        #Trust Store Chrome
        try{
          certutil
        }
        catch{
          Write-Host "Install libnss3 to manage root certificate" -ForegroundColor Blue
          sudo apt-get install libnss3-tools
        }

        if(Test-Path "$HOME/.pki/"){
          Write-Host "Remove Root CA for Chrome" -ForegroundColor Green
          certutil -d sql:$HOME/.pki/nssdb -D -n "$($PkiName)"
        }

        #Trust Store Firefox
        $ListItem = Get-ChildItem -Path $HOME/.mozilla/firefox/
        $firefoxRegex = '[a-z0-9]{8}.default'

        foreach($item in $ListItem){
            if($item -CMatch $firefoxRegex){
                Write-Host "Remove Root CA for Firefox" -ForegroundColor Green
                certutil -d sql:$item/ -D -n "$($PkiName)"
                break;
            }
        }
    }
}

Export-ModuleMember -Function Request-Certificate, Save-CertificateOnServer, Get-LocalCertificates, Remove-LocalCertificate, Save-RootCaCertificate, Install-TrustStoreCertificate, Remove-TrustStoreCertificate