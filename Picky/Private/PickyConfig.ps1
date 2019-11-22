. "$PSScriptRoot/../Private/FileHelper.ps1"
. "$PSScriptRoot/../Private/PlatformHelper.ps1"

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