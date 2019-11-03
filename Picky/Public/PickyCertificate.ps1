. "$PSScriptRoot/../Private/PickyConfig.ps1"
. "$PSScriptRoot/../Private/RSAHelper.ps1"
. "$PSScriptRoot/../Private/FileHelper.ps1"

function Request-Certificate(
    [Parameter(Mandatory=$true)]
    [string]$Subject,
    [Parameter(Mandatory=$true)]
    [string]$PickyApiKey,
    [string]$PickyUrl
){
    if(!($PickyUrl)){
        $PickyUrl = 'http://127.0.0.1:12345'
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
    
        $certificate_path = "$picky_certificate_path/$guid.crt"
        Add-PathIfNotExist $certificate_path
        $certificate_path = Resolve-Path -Path $certificate_path

        $private_key_path = "$picky_certificate_path/$guid.key"
        Add-PathIfNotExist $private_key_path
        $private_key_path = Resolve-Path -Path $private_key_path

        $csr_pem_path = "$picky_certificate_path/$guid.csr"
        Add-PathIfNotExist $csr_pem_path
        $csr_pem_path = Resolve-Path -Path $csr_pem_path

        $Utf8NoBomEncoding = [System.Text.UTF8Encoding]::new($False)

        [System.IO.File]::WriteAllLines($csr_pem_path, $csr_pem, $Utf8NoBomEncoding)
        [System.IO.File]::WriteAllLines($private_key_path, $privateKey, $Utf8NoBomEncoding)
        [System.IO.File]::WriteAllLines($certificate_path, $certificate, $Utf8NoBomEncoding)

        Write-Host $guid
    }
}

function Save-CertificateOnServer(
    [Parameter(Mandatory=$true)]
    [string]$PickyApiKey,
    [Parameter(Mandatory=$true)]
    [string]$CertificateID,
    [string]$PickyUrl
){
    if(!($PickyUrl)){
        $PickyUrl = 'http://127.0.0.1:12345'
    }

    $picky_certificate_path = Get-PickyConfig

    $certificate = Get-Content -Path "$picky_certificate_path/$CertificateID.crt" -Raw
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

function Remove-Certificate(
    [Parameter(Mandatory=$true)]
    [string]$CertificateID
){
    $picky_certificate_path = Get-PickyConfig
    
    Remove-Item -Path "$picky_certificate_path/$CertificateID.key" -Force
    Remove-Item -Path "$picky_certificate_path/$CertificateID.crt" -Force
    Remove-Item -Path "$picky_certificate_path/$CertificateID.csr" -Force
}

function Get-Certificates(){
    $picky_certificate_path = Get-PickyConfig
    $ListItem = Get-ChildItem -Path $picky_certificate_path

    $certificateRegex = '[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}.crt'
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

Export-ModuleMember -Function Request-Certificate, Save-CertificateOnServer, Get-Certificates, Remove-Certificate