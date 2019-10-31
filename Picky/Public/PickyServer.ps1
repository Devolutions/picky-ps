function Start-PickyServer(
    [string]$PickyUrl,
    [string]$PickyApiKey,
    [string]$PickyDockerImage,
    [string]$PickyRealm,
    [string]$PickyBackend,
    [string]$PickyDatabaseUrl
){
    $PickyPort = "12345"
    if(!($PickyUrl)){
        $PickyUrl = 'http://127.0.0.1:12345'
    }
    else{
        $uri = [System.Uri]::new($PickyUrl)
        $PickyPort = $uri.Port
    }

    if(!($PickyApiKey)){
        $PickyApiKey = [System.Guid]::NewGuid().ToString().ToUpper()
    }
    if(!($PickyDockerImage)){
        $PickyDockerImage = 'devolutions/picky:3.3.0-buster-dev'
    }
    if(!($PickyRealm)){
        $PickyRealm = 'wayk.net'
    }
    if(!($PickyBackend)){
        $PickyBackend = 'mongodb'
    }
    if(!($PickyDatabaseUrl)){
        $PickyDatabaseUrl = 'mongodb://picky-mongo:27017'
    }

    & 'docker' 'run' '-d' '--network=picky' '--name' 'picky-mongo' 'library/mongo:4.1-bionic'
    [void](WaitForContainerRunning('picky-mongo'))

    & 'docker' 'run' '-p' "$PickyPort`:$PickyPort" '-d' '--network=picky' '--name' 'picky-server'`
        '-e' "PICKY_REALM=$PickyRealm" `
        '-e' "PICKY_API_KEY=$PickyApiKey" `
        '-e' "PICKY_BACKEND=$PickyBackend" `
        '-e' "PICKY_DATABASE_URL=$PickyDatabaseUrl" `
        "$PickyDockerImage"

    [void](WaitForContainerRunning('picky-server'))

    $s = 0
    $code = 400
    while($s -lt 30){
        Start-Sleep -Seconds 2
        try{
            $s = $s + 2
            $result = Invoke-WebRequest -Uri "$PickyUrl/health" -Method GET
            $code = $result.StatusCode
            if($code -eq 200){
                break;
            }
        }
        catch{
            #miam
        }
    }
}

function Stop-PickyServer(){
    & docker stop picky-mongo
    & docker container rm picky-mongo
    & docker stop picky-server
    & docker container rm picky-server
}

function WaitForContainerRunning{
    param(
        [string]$containerId
    )

    $s = 0
    $running = docker inspect -f '{{.State.Running}}' $containerId
    while($s -lt 30){
        if($running -eq 'true'){
            break;
        }

        Start-Sleep -Seconds 2
        $running = docker inspect -f '{{.State.Running}}' $containerId
        $s = $s + 2
    }
}

Export-ModuleMember -Function Start-PickyServer, Stop-PickyServer