function Add-PathIfNotExist(
	[string] $path,
	[bool] $isFolder
)
{
	if($isFolder) {
		if (!(Test-Path $path)) {
		    $_ = New-Item -path $path -ItemType Directory -Force
		}
	}
	else {
		if (!(Test-Path $path))	{
            $_ = New-Item -path $path -ItemType File -Force
		}
	}
}

function New-TemporaryDirectory()
{
	$parent = [System.IO.Path]::GetTempPath()
	$name = [System.IO.Path]::GetRandomFileName()
	return New-Item -ItemType Directory -Path (Join-Path $parent $name)
}