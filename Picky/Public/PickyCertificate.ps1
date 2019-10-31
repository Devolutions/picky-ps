function Register-Certificate(
    [Parameter(Mandatory=$true)]
    [string]$PickyRealm,
    [Parameter(Mandatory=$true)]
    [string]$PickyApiKey,
    [string]$PickyUrl
){
    if(!($PickyUrl)){
        $PickyUrl = 'http://127.0.0.1:12345'
    }

    $key_size = 2048
    $subject = "CN=${PickyRealm}"
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

    Invoke-RestMethod -Uri $PickyUrl/signcert/ -Method 'POST' `
        -ContentType 'application/pkcs10' `
        -Headers $headers `
        -Body $csr_der
}

Export-ModuleMember -Function Register-Certificate