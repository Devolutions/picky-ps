function Start-PickyServer(
    [Parameter(Mandatory=$true, HelpMessage="Picky Server URL")]
    [string]$PickyUrl,
    [string]$PickyApiKey,
    [string]$PickyDockerImage,
    [string]$PickyRealm,
    [string]$PickyBackend,
    [string]$PickyDatabaseUrl
){
    $uri = [System.Uri]::new($PickyUrl)
    $PickyPort = $uri.Port

    if(!($PickyApiKey)){
        $PickyApiKey = [System.Guid]::NewGuid().ToString().ToUpper()
    }
    if(!($PickyDockerImage)){
        $PickyDockerImage = 'devolutions/picky:4.1.0-buster-dev'
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

    [void](Create-Network)

    $mongo = $(docker container ls -qf "name=picky-mongo")
    if(!($mongo)){
        & 'docker' 'run' '-p' '27017:27017' '-d' '--network=picky' '--name' 'picky-mongo' 'library/mongo:4.1-bionic'
        [void](WaitForContainerRunning('picky-mongo'))
    }
    else{
        Write-Host "mongodb is already running"
    }

    $server = $(docker container ls -qf "name=picky-server")
    if(!($server)){
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
    else{
        Write-Host "docker-server is already running, you can use Restart-PickyServer"
    }
}

function Stop-PickyServer(){
    $server = $(docker container ls -qf "name=picky-server")
    $mongo = $(docker container ls -qf "name=picky-mongo")

    if($mongo){
        & docker stop picky-mongo
        & docker container rm picky-mongo
    }

    if($server){
        & docker stop picky-server
        & docker container rm picky-server
    }
}

function Restart-PickyServer(
    [string]$PickyUrl,
    [string]$PickyApiKey,
    [string]$PickyDockerImage,
    [string]$PickyRealm,
    [string]$PickyBackend,
    [string]$PickyDatabaseUrl){
    Stop-PickyServer
    Start-PickyServer $PickyUrl $PickyApiKey $PickyDockerImage $PickyRealm $PickyBackend $PickyDatabaseUrl
}   

function Create-Network{
    $network = $(docker network ls -qf "name=picky")
    if(!($network)){
        docker network create picky
    }
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

Export-ModuleMember -Function Start-PickyServer, Stop-PickyServer, Restart-PickyServer