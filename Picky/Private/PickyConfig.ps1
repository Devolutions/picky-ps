. "$PSScriptRoot/../Private/FileHelper.ps1"

function Get-PickyConfig(){
    if (Get-IsWindows)	{
		Add-PathIfNotExist "$Env:APPDATA\Picky" $true
		$DataPath = $Env:APPDATA + '\Picky';
	} elseif ($IsMacOS) {
		Add-PathIfNotExist "~/Library/Application Support/Picky" $true
		$DataPath = '~/Library/Application Support/Picky'
	} elseif ($IsLinux) {
		Add-PathIfNotExist "~/.config/Picky" $true
		$DataPath = '~/.config/Picky'
    }
    
    return $DataPath
}

function Get-IsWindows
{
    if (-Not (Test-Path 'variable:global:IsWindows')) {
        return $true # Windows PowerShell 5.1 or earlier
    } else {
        return $IsWindows
    }
}