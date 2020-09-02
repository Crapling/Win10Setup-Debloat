$tweaks = @(
"RememberOnExplorerRestart",
"EnableRegistryBackup",
"PinSystemAppsToStart",
"ChangeFoldersDefaultDrive"
)

##############
# other functionality
##############

# Save all opened folders in order to restore them after File Explorer restart
function RememberOnExplorerRestart {
	Clear-Variable -Name OpenedFolders -Force -ErrorAction Ignore
	$OpenedFolders = {(New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process {$_.Document.Folder.Self.Path}}.Invoke()
	# Restart explorer in order to take changes in effect
		Stop-Process -Name explorer -Force
	# Restore closed folders
		foreach ($OpenedFolder in $OpenedFolders)
		{
			if (Test-Path -Path $OpenedFolder)
			{
				Invoke-Item -Path $OpenedFolder
			}
		}
}

# Turn on automatic backup the system registry to the %SystemRoot%\System32\config\RegBack folder
function EnableRegistryBackup{
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Name EnablePeriodicBackup -PropertyType DWord -Value 1 -Force
}

# Pin useful system apps shortcuts to Start
function PinSystemAppsToStart {
if (Test-Path -Path $PSScriptRoot\syspin.exe)
{
	$syspin = $true
}
else
{
	try
	{
		# Downloading syspin.exe
		# http://www.technosys.net/products/utils/pintotaskbar
		# SHA256: 6967E7A3C2251812DD6B3FA0265FB7B61AADC568F562A98C50C345908C6E827
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		if ((Invoke-WebRequest -Uri https://www.google.com -UseBasicParsing -DisableKeepAlive -Method Head).StatusDescription)
		{
			$Parameters = @{
				Uri = "https://github.com/farag2/Windows-10-Setup-Script/raw/master/Start%20menu%20pinning/syspin.exe"
				OutFile = "$PSScriptRoot\syspin.exe"
				Verbose = [switch]::Present
			}
			Invoke-WebRequest @Parameters
			$syspin = $true
		}
	}
	catch
	{
		if ($Error.Exception.Status -eq "NameResolutionFailure")
		{
				Write-Warning -Message "No Internet connection" -ErrorAction SilentlyContinue
		}
	}
}

if ($syspin -eq $true)
{
	# Pin "Control Panel" to Start
	$Items = (New-Object -ComObject Shell.Application).NameSpace("shell:::{4234d49b-0245-4df3-b780-3893943456e1}").Items()
	$ControlPanelLocalizedName = ($Items | Where-Object -FilterScript {$_.Path -eq "Microsoft.Windows.ControlPanel"}).Name

		Write-Verbose -Message "`"$ControlPanelLocalizedName`" shortcut is being pinned to Start" -Verbose

	# Check whether the Control Panel shortcut was ever pinned
	if (Test-Path -Path "$env:APPDATA\Microsoft\Windows\Start menu\Programs\$ControlPanelLocalizedName.lnk")
	{
		$Arguments = @"
"$env:APPDATA\Microsoft\Windows\Start menu\Programs\$ControlPanelLocalizedName.lnk" "51201"
"@
		Start-Process -FilePath $PSScriptRoot\syspin.exe -WindowStyle Hidden -ArgumentList $Arguments -Wait
	}
	else
	{
		# The "Pin" verb is not available on the control.exe file so the shortcut has to be created
		$Shell = New-Object -ComObject Wscript.Shell
		$Shortcut = $Shell.CreateShortcut("$env:SystemRoot\System32\$ControlPanelLocalizedName.lnk")
		$Shortcut.TargetPath = "$env:SystemRoot\System32\control.exe"
		$Shortcut.Save()

		$Arguments = @"
"$env:SystemRoot\System32\$ControlPanelLocalizedName.lnk" "51201"
"@
		Start-Process -FilePath $PSScriptRoot\syspin.exe -WindowStyle Hidden -ArgumentList $Arguments -Wait
		Remove-Item -Path "$env:SystemRoot\System32\$ControlPanelLocalizedName.lnk" -Force
	}
		# restart Start Menu
		Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction Ignore
}
}

##############
# change drive functions
##############

<#
.SYNOPSIS
	The "Show menu" function using PowerShell with the up/down arrow keys and enter key to make a selection
.EXAMPLE
	ShowMenu -Menu $ListOfItems -Default $DefaultChoice
.NOTES
	Doesn't work in PowerShell ISE
#>
function ShowMenu
{
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[string]
		$Title,

		[Parameter(Mandatory = $true)]
		[array]
		$Menu,

		[Parameter(Mandatory = $true)]
		[int]
		$Default
	)

	Write-Information -MessageData $Title -InformationAction Continue

	$minY = [Console]::CursorTop
	$y = [Math]::Max([Math]::Min($Default, $Menu.Count), 0)
	do
	{
		[Console]::CursorTop = $minY
		[Console]::CursorLeft = 0
		$i = 0
		foreach ($item in $Menu)
		{
			if ($i -ne $y)
			{
				Write-Information -MessageData ('  {0}. {1}  ' -f ($i+1), $item) -InformationAction Continue
			}
			else
			{
				Write-Information -MessageData ('[ {0}. {1} ]' -f ($i+1), $item) -InformationAction Continue
			}
			$i++
		}

		$k = [Console]::ReadKey()
		switch ($k.Key)
		{
			"UpArrow"
			{
				if ($y -gt 0)
				{
					$y--
				}
			}
			"DownArrow"
			{
				if ($y -lt ($Menu.Count - 1))
				{
					$y++
				}
			}
			"Enter"
			{
				return $Menu[$y]
			}
		}
	}
	while ($k.Key -notin ([ConsoleKey]::Escape, [ConsoleKey]::Enter))
}

# Change location of the various folders
function UserShellFolder
{

<#
.SYNOPSIS
	Change location of the each user folders using SHSetKnownFolderPath function
.EXAMPLE
	UserShellFolder -UserFolder Desktop -FolderPath "C:\Desktop"
.NOTES
	User files or folders won't me moved to the new location
#>
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateSet("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")]
		[string]
		$UserFolder,

		[Parameter(Mandatory = $true)]
		[string]
		$FolderPath
	)
	function KnownFolderPath
	{
	<#
	.SYNOPSIS
		Redirect user folders to a new location
	.EXAMPLE
		KnownFolderPath -KnownFolder Desktop -Path "C:\Desktop"
	.NOTES
		User files or folders won't me moved to the new location
	#>
		[CmdletBinding()]
		param
		(
			[Parameter(Mandatory = $true)]
			[ValidateSet("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos")]
			[string]
			$KnownFolder,

			[Parameter(Mandatory = $true)]
			[string]
			$Path
		)

		$KnownFolders = @{
			"Desktop"	= @("B4BFCC3A-DB2C-424C-B029-7FE99A87C641");
			"Documents"	= @("FDD39AD0-238F-46AF-ADB4-6C85480369C7", "f42ee2d3-909f-4907-8871-4c22fc0bf756");
			"Downloads"	= @("374DE290-123F-4565-9164-39C4925E467B", "7d83ee9b-2244-4e70-b1f5-5393042af1e4");
			"Music"		= @("4BD8D571-6D19-48D3-BE97-422220080E43", "a0c69a99-21c8-4671-8703-7934162fcf1d");
			"Pictures"	= @("33E28130-4E1E-4676-835A-98395C3BC3BB", "0ddd015d-b06c-45d5-8c4c-f59713854639");
			"Videos"	= @("18989B1D-99B5-455B-841C-AB7C74E4DDFC", "35286a68-3c57-41a1-bbb1-0eae73d76c95");
		}

		$Signature = @{
			Namespace = "WinAPI"
			Name = "KnownFolders"
			Language = "CSharp"
			MemberDefinition = @"
[DllImport("shell32.dll")]
public extern static int SHSetKnownFolderPath(ref Guid folderId, uint flags, IntPtr token, [MarshalAs(UnmanagedType.LPWStr)] string path);
"@
		}
		if (-not ("WinAPI.KnownFolders" -as [type]))
		{
			Add-Type @Signature
		}

		foreach ($guid in $KnownFolders[$KnownFolder])
		{
			[WinAPI.KnownFolders]::SHSetKnownFolderPath([ref]$guid, 0, 0, $Path)
		}
		(Get-Item -Path $Path -Force).Attributes = "ReadOnly"
	}

	$UserShellFoldersRegName = @{
		"Desktop"	=	"Desktop"
		"Documents"	=	"Personal"
		"Downloads"	=	"{374DE290-123F-4565-9164-39C4925E467B}"
		"Music"		=	"My Music"
		"Pictures"	=	"My Pictures"
		"Videos"	=	"My Video"
	}

	$UserShellFoldersGUID = @{
		"Desktop"	=	"{754AC886-DF64-4CBA-86B5-F7FBF4FBCEF5}"
		"Documents"	=	"{F42EE2D3-909F-4907-8871-4C22FC0BF756}"
		"Downloads"	=	"{7D83EE9B-2244-4E70-B1F5-5393042AF1E4}"
		"Music"		=	"{A0C69A99-21C8-4671-8703-7934162FCF1D}"
		"Pictures"	=	"{0DDD015D-B06C-45D5-8C4C-F59713854639}"
		"Videos"	=	"{35286A68-3C57-41A1-BBB1-0EAE73D76C95}"
	}

	# Hidden desktop.ini for each type of user folders
	$DesktopINI = @{
		"Desktop"	=	"",
						"[.ShellClassInfo]",
						"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21769",
						"IconResource=%SystemRoot%\system32\imageres.dll,-183"
		"Documents"	=	"",
						"[.ShellClassInfo]",
						"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21770",
						"IconResource=%SystemRoot%\system32\imageres.dll,-112",
						"IconFile=%SystemRoot%\system32\shell32.dll",
						"IconIndex=-235"
		"Downloads"	=	"",
						"[.ShellClassInfo]","LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21798",
						"IconResource=%SystemRoot%\system32\imageres.dll,-184"
		"Music"		=	"",
						"[.ShellClassInfo]","LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21790",
						"InfoTip=@%SystemRoot%\system32\shell32.dll,-12689",
						"IconResource=%SystemRoot%\system32\imageres.dll,-108",
						"IconFile=%SystemRoot%\system32\shell32.dll","IconIndex=-237"
		"Pictures"	=	"",
						"[.ShellClassInfo]",
						"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21779",
						"InfoTip=@%SystemRoot%\system32\shell32.dll,-12688",
						"IconResource=%SystemRoot%\system32\imageres.dll,-113",
						"IconFile=%SystemRoot%\system32\shell32.dll",
						"IconIndex=-236"
		"Videos"	=	"",
						"[.ShellClassInfo]",
						"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21791",
						"InfoTip=@%SystemRoot%\system32\shell32.dll,-12690",
						"IconResource=%SystemRoot%\system32\imageres.dll,-189",
						"IconFile=%SystemRoot%\system32\shell32.dll","IconIndex=-238"
	}

	# Determining the current user folder path
	$UserShellFolderRegValue = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name $UserShellFoldersRegName[$UserFolder]
	if ($UserShellFolderRegValue -ne $FolderPath)
	{
		if ((Get-ChildItem -Path $UserShellFolderRegValue | Measure-Object).Count -ne 0)
		{
	
			
				Write-Error -Message "Some files left in the $UserShellFolderRegValue folder. Move them manually to a new location" -ErrorAction SilentlyContinue
			
		}

		# Creating a new folder if there is no one
		if (-not (Test-Path -Path $FolderPath))
		{
			New-Item -Path $FolderPath -ItemType Directory -Force
		}

		KnownFolderPath -KnownFolder $UserFolder -Path $FolderPath
		New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name $UserShellFoldersGUID[$UserFolder] -PropertyType ExpandString -Value $FolderPath -Force

		Set-Content -Path "$FolderPath\desktop.ini" -Value $DesktopINI[$UserFolder] -Encoding Unicode -Force
		(Get-Item -Path "$FolderPath\desktop.ini" -Force).Attributes = "Hidden", "System", "Archive"
		(Get-Item -Path "$FolderPath\desktop.ini" -Force).Refresh()
	}
}

# changing default location drive for Desktop,Documents,Downloads,Music,Pictures,Videos,Program Files,Program Files (x86),Temp
function ChangeFoldersDefaultDrive{

# Store all drives letters to use them within ShowMenu function
	Write-Verbose "Retrieving drives..." -Verbose

$DriveLetters = @((Get-Disk | Where-Object -FilterScript {$_.BusType -ne "USB"} | Get-Partition | Get-Volume | Where-Object -FilterScript {$null -ne $_.DriveLetter}).DriveLetter | Sort-Object)

if ($DriveLetters.Count -gt 1)
{
	# If the number of disks is more than one, set the second drive in the list as default drive
	$Default = 1
}
else
{
	$Default = 0
}

# Desktop
	$Message = "To change the location of the Desktop folder enter the required letter"
	Write-Warning -Message "`nFiles will not be moved"
	$Options = "&Change", "&Skip"
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		$Title = "`nSelect the drive where the `"Desktop`" folder will be moved to"
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Desktop -FolderPath "${SelectedDrive}:\Users\$env:UserName\Desktop"
	}
	"1"
	{
			Write-Verbose -Message "Skipped" -Verbose
	}
}

# Documents
$Title = ""
	$Message = "To change the location of the Documents folder enter the required letter"
	Write-Warning -Message "`nFiles will not be moved"
	$Options = "&Change", "&Skip"

$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		
		$Title = "`nSelect the drive where the `"Documents`" folder will be moved to"

		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Documents -FolderPath "${SelectedDrive}:\Users\$env:UserName\Documents"
	}
	"1"
	{
			Write-Verbose -Message "Skipped" -Verbose
	}
}

# Downloads
$Title = ""
	$Message = "To change the location of the Downloads folder enter the required letter"
	Write-Warning -Message "`nFiles will not be moved"
	$Options = "&Change", "&Skip"

$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		$Title = "`nSelect the drive where the `"Downloads`" folder will be moved to"
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Downloads -FolderPath "${SelectedDrive}:\Users\$env:UserName\Downloads"
	}
	"1"
	{
			Write-Verbose -Message "Skipped" -Verbose
	}
}

# Music
$Title = ""
	$Message = "To change the location of the Music folder enter the required letter"
	Write-Warning -Message "`nFiles will not be moved"
	$Options = "&Change", "&Skip"

$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		$Title = "`nSelect the drive where the `"Music`" folder will be moved to"
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Music -FolderPath "${SelectedDrive}:\Users\$env:UserName\Music"
	}
	"1"
	{
			write-Verbose -Message "Skipped" -Verbose
	}
}


# Pictures
$Title = ""

	$Message = "To change the location of the Pictures folder enter the required letter"
	Write-Warning -Message "`nFiles will not be moved"
	$Options = "&Change", "&Skip"

$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		$Title = "`nSelect the drive where the `"Pictures`" folder will be moved to"
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Pictures -FolderPath "${SelectedDrive}:\Users\$env:UserName\Pictures"
	}
	"1"
	{
			Write-Verbose -Message "Skipped" -Verbose
	}
}

# Videos
$Title = ""
	$Message = "To change the location of the Videos folder enter the required letter"
	Write-Warning -Message "`nFiles will not be moved"
	$Options = "&Change", "&Skip"
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
		$Title = "`nSelect the drive where the `"Videos`" folder will be moved to"
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		UserShellFolder -UserFolder Videos -FolderPath "${SelectedDrive}:\Users\$env:UserName\Videos"
	}
	"1"
	{
			Write-Verbose -Message "Skipped" -Verbose
	}
}

# Program Files
$Title = ""
	$Message = "To change the location of the Program Files folder enter the required letter"
	Write-Warning -Message "`nFiles will not be moved"
	$Options = "&Change", "&Skip"
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
			$Title = "`nSelect the drive where the `"Program Files`" folder will be moved to"
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		Write-Output "Changing Program Files Folder to $SelectedDrive..."
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "ProgramFilesDir" -Type String -Value "${SelectedDrive}:\Program Files"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "ProgramW6432Dir" -Type String -Value "${SelectedDrive}:\Program Files"
        
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "CommonFilesDir" -Type String -Value "${SelectedDrive}:\Program Files\Common Files"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "CommonW6432Dir" -Type String -Value "${SelectedDrive}:\Program Files\Common Files"
    }
	"1"
	{
			Write-Verbose -Message "Skipped" -Verbose
}
}

# Program Files(x86)
$Title = ""
	$Message = "To change the location of the Program Files (x86) folder enter the required letter"
	Write-Warning -Message "`nFiles will not be moved"
	$Options = "&Change", "&Skip"
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
			$Title = "`nSelect the drive where the `"Program Files (x86)`" folder will be moved to"
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		Write-Output "Changing Program Files Folder to $SelectedDrive..."
	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "ProgramFilesDir (x86)" -Type String -Value "${SelectedDrive}:\Program Files (x86)"
    
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "CommonFilesDir (x86)" -Type String -Value "${SelectedDrive}:\Program Files (x86)\Common Files"
    }
	"1"
	{
			Write-Verbose -Message "Skipped" -Verbose
}
}

# Temp
$Title = ""
	$Message = "To change the location of the Temp folder enter the required letter"
	Write-Warning -Message "`nFiles will not be moved"
	$Options = "&Change", "&Skip"
$DefaultChoice = 1
$Result = $Host.UI.PromptForChoice($Title, $Message, $Options, $DefaultChoice)

switch ($Result)
{
	"0"
	{
			$Title = "`nSelect the drive where the `"Temp`" folder will be moved to"
		$SelectedDrive = ShowMenu -Title $Title -Menu $DriveLetters -Default $Default
		Write-Output "Changing Temp Folder to $SelectedDrive..."
        [System.Environment]::SetEnvironmentVariable("TEMP","${SelectedDrive}:\Users\$env:UserName\AppData\Local\Temp",[System.EnvironmentVariableTarget]::User)
        [System.Environment]::SetEnvironmentVariable("TEMP","${SelectedDrive}:\Users\$env:UserName\AppData\Local\Temp",[System.EnvironmentVariableTarget]::Machine)
        [System.Environment]::SetEnvironmentVariable("TMP","${SelectedDrive}:\Users\$env:UserName\AppData\Local\Temp",[System.EnvironmentVariableTarget]::User)
        [System.Environment]::SetEnvironmentVariable("TMP","${SelectedDrive}:\Users\$env:UserName\AppData\Local\Temp",[System.EnvironmentVariableTarget]::Machine)
    }
	"1"
	{
			Write-Verbose -Message "Skipped" -Verbose
}
}
}
# Call the desired tweak functions
$tweaks | ForEach { Invoke-Expression $_ }