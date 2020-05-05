<#
.SYNOPSIS
Customers with strict IT security requirements often mandate that no identifying information leaves the premises.

If you need to send a trace or log file to Microsoft or another vendor, this script will consistently de-idenfity it for you.

.DESCRIPTION
This script will perform a find/replace on your log or trace file, using values from a CSV file you provide. Any IP addresses that remain in the original file will be turned into dummy values "aa.bb.cc.nn", where "nn" is an incrementing number. All instances of the same IP address in your source file will be turned into same dummy value.


.NOTES
	Version				: 1.0
	Date				: 21st August 2019
	Author				: Greig Sheridan
	Credits are at the bottom of the script

	Revision History 	:
				v1.0: 21st August 2019
					Initial release.


.LINK
	https://greiginsydney.com/New-ObfuscatedFile-ps1

.EXAMPLE
	.\New-ObfuscatedFile.ps1

	Description
	-----------
	With no input parameters passed to it, the script will dump this help text to screen.


.EXAMPLE
	.\New-ObfuscatedFile.ps1 -InputFile logfile.txt

	Description
	-----------
	The log file will have its IP addresses replaced with dummy values and the file saved as logfile-new.txt

.EXAMPLE
	.\New-ObfuscatedFile.ps1 -InputFile logfile.txt -Overwrite

	Description
	-----------
	The log file will have its IP addresses replaced with dummy values and the file saved

.EXAMPLE
	.\New-ObfuscatedFile.ps1 -InputFile logfile.txt -OutputFile logfile-OK2send.txt

	Description
	-----------
	The log file will have its IP addresses replaced with dummy values and the file saved as logfile-OK2send.txt

.EXAMPLE
	.\New-ObfuscatedFile.ps1 -InputFile logfile.txt -OutputFile logfile-OK2send.txt -CsvReplaceFile replacevalues.csv

	Description
	-----------
	The log file will have any hostnames and IP addresses that are found in 'replacevalues.csv' replaced with the
	substitute names in the file. Any unchanged IP addresses will be replaced with dummy values.
	The resulting file will be saved as logfile-OK2send.txt

.EXAMPLE
	Get-ChildItem *.log [-recurse] | foreach { .\New-ObfuscatedFile.ps1 -InputFile $_.Fullname -Overwrite -ReplaceFile MyReplaceFile.csv -SkipUpdateCheck}

	Description
	-----------
	Batch it! All .log files in the source directory (and all those beneath it if the optional "-recurse" flag is specified) will be
	updated with the find/replace values from 'MyReplaceFile.csv', then any unchanged IP addresses will be replaced with dummy values.
	Each original file over-written with the new content.


.PARAMETER InputFile
		String.

.PARAMETER OutputFile
		String.

.PARAMETER CsvReplaceFile
		String.

.PARAMETER OverWrite
		Switch. Overwrite the InputFile with the updated content.

.PARAMETER SkipIp
		Switch. Skip the generic IP replacement. (Only perform replacements from the CsvReplaceFile)

.PARAMETER SkipUpdateCheck
		Switch. Don't check for an update. (Make sure you specify this if batching or automating the script.)

#>

[CmdletBinding(SupportsShouldProcess = $False, DefaultParameterSetName='None')]
Param(
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[string]$InputFile,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[string]$OutputFile,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[string]$CsvReplaceFile,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[switch]$Overwrite,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[switch]$SkipIp,
	[Parameter(ParameterSetName='Default', Mandatory = $false)]
	[switch]$SkipUpdateCheck

)


#--------------------------------
# START FUNCTIONS ---------------
#--------------------------------

function Get-UpdateInfo
{
  <#
	  .SYNOPSIS
	  Queries an online XML source for version information to determine if a new version of the script is available.
	  *** This version customised by Greig Sheridan. @greiginsydney https://greiginsydney.com ***

	  .DESCRIPTION
	  Queries an online XML source for version information to determine if a new version of the script is available.

	  .NOTES
	  Version				: 1.2 - See changelog at https://ucunleashed.com/3168 for fixes & changes introduced with each version
	  Wish list				: Better error trapping
	  Rights Required		: N/A
	  Sched Task Required	: No
	  Lync/Skype4B Version	: N/A
	  Author/Copyright		: © Pat Richard, Office Servers and Services (Skype for Business) MVP - All Rights Reserved
	  Email/Blog/Twitter	: pat@innervation.com  https://ucunleashed.com  @patrichard
	  Donations				: https://www.paypal.me/PatRichard
	  Dedicated Post		: https://ucunleashed.com/3168
	  Disclaimer			: You running this script/function means you will not blame the author(s) if this breaks your stuff. This script/function
							is provided AS IS without warranty of any kind. Author(s) disclaim all implied warranties including, without limitation,
							any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use
							or performance of the sample scripts and documentation remains with you. In no event shall author(s) be held liable for
							any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss
							of business information, or other pecuniary loss) arising out of the use of or inability to use the script or
							documentation. Neither this script/function, nor any part of it other than those parts that are explicitly copied from
							others, may be republished without author(s) express written permission. Author(s) retain the right to alter this
							disclaimer at any time. For the most up to date version of the disclaimer, see https://ucunleashed.com/code-disclaimer.
	  Acknowledgements		: Reading XML files
							http://stackoverflow.com/questions/18509358/how-to-read-xml-in-powershell
							http://stackoverflow.com/questions/20433932/determine-xml-node-exists
	  Assumptions			: ExecutionPolicy of AllSigned (recommended), RemoteSigned, or Unrestricted (not recommended)
	  Limitations			:
	  Known issues			:

	  .EXAMPLE
	  Get-UpdateInfo -Title 'New-ObfuscatedFile.ps1'

	  Description
	  -----------
	  Runs function to check for updates to script called 'New-ObfuscatedFile.ps1'.

	  .INPUTS
	  None. You cannot pipe objects to this script.
  #>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
	[string] $title
	)
	try
	{
		[bool] $HasInternetAccess = ([Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet)
		if ($HasInternetAccess)
		{
			write-verbose -message 'Performing update check'
			# ------------------ TLS 1.2 fixup from https://github.com/chocolatey/choco/wiki/Installation#installing-with-restricted-tls
			$securityProtocolSettingsOriginal = [Net.ServicePointManager]::SecurityProtocol
			try {
			  # Set TLS 1.2 (3072). Use integers because the enumeration values for TLS 1.2 won't exist in .NET 4.0, even though they are
			  # addressable if .NET 4.5+ is installed (.NET 4.5 is an in-place upgrade).
			  [Net.ServicePointManager]::SecurityProtocol = 3072
			} catch {
			  write-verbose -message 'Unable to set PowerShell to use TLS 1.2 due to old .NET Framework installed.'
			}
			# ------------------ end TLS 1.2 fixup
			[xml] $xml = (New-Object -TypeName System.Net.WebClient).DownloadString('https://greiginsydney.com/wp-content/version.xml')
			[Net.ServicePointManager]::SecurityProtocol = $securityProtocolSettingsOriginal #Reinstate original SecurityProtocol settings
			$article  = select-XML -xml $xml -xpath ("//article[@title='{0}']" -f ($title))
			[string] $Ga = $article.node.version.trim()
			if ($article.node.changeLog)
			{
				[string] $changelog = 'This version includes: ' + $article.node.changeLog.trim() + "`n`n"
			}
			if ($Ga -gt $ScriptVersion)
			{
				$wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
				$updatePrompt = $wshell.Popup(("Version {0} is available.`n`n{1}Would you like to download it?" -f ($ga), ($changelog)),0,'New version available',68)
				if ($updatePrompt -eq 6)
				{
					Start-Process -FilePath $article.node.downloadUrl
					write-warning -message "Script is exiting. Please run the new version of the script after you've downloaded it."
					exit
				}
				else
				{
					write-verbose -message ('Upgrade to version {0} was declined' -f ($ga))
				}
			}
			elseif ($Ga -eq $ScriptVersion)
			{
				write-verbose -message ('Script version {0} is the latest released version' -f ($Scriptversion))
			}
			else
			{
				write-verbose -message ('Script version {0} is newer than the latest released version {1}' -f ($Scriptversion), ($ga))
			}
		}
		else
		{
		}

	} # end function Get-UpdateInfo
	catch
	{
		write-verbose -message 'Caught error in Get-UpdateInfo'
		if ($Global:Debug)
		{
			$Global:error | Format-List -Property * -Force #This dumps to screen as white for the time being. I haven't been able to get it to dump in red
		}
	}
}

function get-AbsoluteFilePath
{
	param
	(
	[string]$dir,
	[string]$File
	)
	if ([IO.Path]::IsPathRooted($File))
	{
		#It's absolute. Safe to leave.
	}
	else
	{
		#It's relative.
		$File = [IO.Path]::GetFullPath((Join-Path -path $dir -childpath $File))
	}
	return $File
}


#--------------------------------
# END FUNCTIONS -----------------
#--------------------------------


$ScriptVersion = "1.0"
$Error.Clear()

if ($skipupdatecheck)
{
	write-verbose -message 'Skipping update check'
}
else
{
	write-progress -id 1 -Activity 'Initialising' -Status 'Performing update check' -PercentComplete (2)
	Get-UpdateInfo -title 'New-ObfuscatedFile.ps1'
	write-progress -id 1 -Activity 'Initialising' -Status 'Back from performing update check' -PercentComplete (2)
}

if (!($InputFile))
{
	write-warning "You need to specify an -InputFile at the very least!"
	get-help .\New-ObfuscatedFile.ps1
	exit
}

$scriptpath = $MyInvocation.MyCommand.Path
$dir = Split-Path -Path $scriptpath

if (test-path $InputFile)
{
	$MyInputFile = Get-AbsoluteFilePath $dir $inputFile
	$content = (get-content $MyInputFile -encoding ASCII)
}
else
{
	write-warning "Input file ""$($InputFile)"" does not exist. Try again."
	exit
}

if ($OutputFile)
{
	if (test-path $OutputFile)
	{
		$MyOutputFile = Get-AbsoluteFilePath $dir $outputFile
	}
}

if ($CsvReplaceFile)
{
	if (test-path $CsvReplaceFile)
	{
		$MyCsvFile = Get-AbsoluteFilePath $dir $CsvReplaceFile
		$ReplaceList = import-csv $MyCsvFile
		if (($ReplaceList[0].psobject.properties.name -notcontains 'find') -or ($ReplaceList[0].psobject.properties.name -notcontains 'replace'))
		{
			write-warning "The CSV file's headers (the top row) must be named (and formatted) as ""find,replace"""
			write-warning "Please correct and restart"
			exit
		}
	}
	else
	{
		write-warning "Replacement file ""$($ReplaceFileCsv)"" does not exist. Try again."
		exit
	}
}

foreach ($replacement in $ReplaceList)
{
	if (!([string]::IsNullOrEmpty($replacement.find)))
	{
		if ($content -match $replacement.find)
		{
			$content = $content -replace "$($replacement.find)","$($replacement.replace)"
			write-output "Replaced $($Replacement.find) with $($replacement.replace)"
		}
	}
}

if (!($SkipIP))
{
	#Obfuscate any remaining IPs (that aren't the result of a change made above):
	$IpAsRegex = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' # FULL IP
	$ReplaceIP = 1 # This is the dummy suffix we add to each remaining unique IP address in the file
	$OrderedIpList = @()

	$FoundIP = select-string -inputobject $content -pattern $IpAsRegex -AllMatches
	if ($FoundIP.Matches -ne $null)
	{
		$OrderedIpList += $FoundIP.Matches.Value
		$OrderedIpList = $OrderedIpList | sort -descending #If we don't replace in this order, "shorter" IPs will be replaced first, with longer ones then mishandled
		:looping foreach ($IP in $OrderedIpList)
		{
			foreach ($replacement in $ReplaceList)
			{
				#Skip the IPs we've already changed
				if ($IP -match $replacement.replace) { continue looping}
			}
			$content = $content -replace $IP, ('aa.bb.cc.' + $ReplaceIP.ToString()) # Strip the prefix
			write-output "Replaced $($IP) with aa.bb.cc.$($ReplaceIP.ToString())"
			$ReplaceIP ++
		}
	}
}

if ($outputFile)
{
	$content | set-content $OutputFile -encoding ASCII
}
elseif ($overWrite)
{
	$content | set-content $InputFile -encoding ASCII
}
else
{
	# Add the "-new" suffix to the name & overwrite if it already exists
	$content | set-content ([System.IO.Path]::GetFileNameWithoutExtension($InputFile) +
				"-new" + [System.IO.Path]::GetExtension($InputFile)) -encoding ASCII
}



# Search/Replace (for ObfuscateIP) https://www.safaribooksonline.com/library/view/regular-expressions-cookbook/9780596802837/ch07s16.html
# Search/Replace (for ObfuscateIP) http://stackoverflow.com/questions/27169043/powershell-search-matching-string-in-word-document
# Search/Replace (for ObfuscateIP) https://gallery.technet.microsoft.com/office/7c463ad7-0eed-4792-8236-38434f891e0e

#Code signing certificate kindly provided by Digicert:
# SIG # Begin signature block
# MIIceAYJKoZIhvcNAQcCoIIcaTCCHGUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUluW3sJ1OzwxI4s/BzpbskN+5
# /kSgghenMIIFMDCCBBigAwIBAgIQA1GDBusaADXxu0naTkLwYTANBgkqhkiG9w0B
# AQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgQ29kZSBTaWduaW5nIENBMB4XDTIwMDQxNzAwMDAwMFoXDTIxMDcw
# MTEyMDAwMFowbTELMAkGA1UEBhMCQVUxGDAWBgNVBAgTD05ldyBTb3V0aCBXYWxl
# czESMBAGA1UEBxMJUGV0ZXJzaGFtMRcwFQYDVQQKEw5HcmVpZyBTaGVyaWRhbjEX
# MBUGA1UEAxMOR3JlaWcgU2hlcmlkYW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQC0PMhHbI+fkQcYFNzZHgVAuyE3BErOYAVBsCjZgWFMhqvhEq08El/W
# PNdtlcOaTPMdyEibyJY8ZZTOepPVjtHGFPI08z5F6BkAmyJ7eFpR9EyCd6JRJZ9R
# ibq3e2mfqnv2wB0rOmRjnIX6XW6dMdfs/iFaSK4pJAqejme5Lcboea4ZJDCoWOK7
# bUWkoqlY+CazC/Cb48ZguPzacF5qHoDjmpeVS4/mRB4frPj56OvKns4Nf7gOZpQS
# 956BgagHr92iy3GkExAdr9ys5cDsTA49GwSabwpwDcgobJ+cYeBc1tGElWHVOx0F
# 24wBBfcDG8KL78bpqOzXhlsyDkOXKM21AgMBAAGjggHFMIIBwTAfBgNVHSMEGDAW
# gBRaxLl7KgqjpepxA8Bg+S32ZXUOWDAdBgNVHQ4EFgQUzBwyYxT+LFH+GuVtHo2S
# mSHS/N0wDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGA1Ud
# HwRwMG4wNaAzoDGGL2h0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3Vy
# ZWQtY3MtZzEuY3JsMDWgM6Axhi9odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc2hh
# Mi1hc3N1cmVkLWNzLWcxLmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwDATAqMCgG
# CCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAEE
# ATCBhAYIKwYBBQUHAQEEeDB2MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wTgYIKwYBBQUHMAKGQmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFNIQTJBc3N1cmVkSURDb2RlU2lnbmluZ0NBLmNydDAMBgNVHRMB
# Af8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCtV/Nu/2vgu+rHGFI6gssYWfYLEwXO
# eJqOYcYYjb7dk5sRTninaUpKt4WPuFo9OroNOrw6bhvPKdzYArXLCGbnvi40LaJI
# AOr9+V/+rmVrHXcYxQiWLwKI5NKnzxB2sJzM0vpSzlj1+fa5kCnpKY6qeuv7QUCZ
# 1+tHunxKW2oF+mBD1MV2S4+Qgl4pT9q2ygh9DO5TPxC91lbuT5p1/flI/3dHBJd+
# KZ9vYGdsJO5vS4MscsCYTrRXvgvj0wl+Nwumowu4O0ROqLRdxCZ+1X6a5zNdrk4w
# Dbdznv3E3s3My8Axuaea4WHulgAvPosFrB44e/VHDraIcNCx/GBKNYs8MIIFMDCC
# BBigAwIBAgIQBAkYG1/Vu2Z1U0O1b5VQCDANBgkqhkiG9w0BAQsFADBlMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0Ew
# HhcNMTMxMDIyMTIwMDAwWhcNMjgxMDIyMTIwMDAwWjByMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29kZSBTaWduaW5n
# IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+NOzHH8OEa9ndwfT
# CzFJGc/Q+0WZsTrbRPV/5aid2zLXcep2nQUut4/6kkPApfmJ1DcZ17aq8JyGpdgl
# rA55KDp+6dFn08b7KSfH03sjlOSRI5aQd4L5oYQjZhJUM1B0sSgmuyRpwsJS8hRn
# iolF1C2ho+mILCCVrhxKhwjfDPXiTWAYvqrEsq5wMWYzcT6scKKrzn/pfMuSoeU7
# MRzP6vIK5Fe7SrXpdOYr/mzLfnQ5Ng2Q7+S1TqSp6moKq4TzrGdOtcT3jNEgJSPr
# CGQ+UpbB8g8S9MWOD8Gi6CxR93O8vYWxYoNzQYIH5DiLanMg0A9kczyen6Yzqf0Z
# 3yWT0QIDAQABo4IBzTCCAckwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E
# BAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwTwYDVR0g
# BEgwRjA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRp
# Z2ljZXJ0LmNvbS9DUFMwCgYIYIZIAYb9bAMwHQYDVR0OBBYEFFrEuXsqCqOl6nED
# wGD5LfZldQ5YMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqG
# SIb3DQEBCwUAA4IBAQA+7A1aJLPzItEVyCx8JSl2qB1dHC06GsTvMGHXfgtg/cM9
# D8Svi/3vKt8gVTew4fbRknUPUbRupY5a4l4kgU4QpO4/cY5jDhNLrddfRHnzNhQG
# ivecRk5c/5CxGwcOkRX7uq+1UcKNJK4kxscnKqEpKBo6cSgCPC6Ro8AlEeKcFEeh
# emhor5unXCBc2XGxDI+7qPjFEmifz0DLQESlE/DmZAwlCEIysjaKJAL+L3J+HNdJ
# RZboWR3p+nRka7LrZkPas7CM1ekN3fYBIM6ZMWM9CBoYs4GbT8aTEAb8B4H6i9r5
# gkn3Ym6hU/oSlBiFLpKR6mhsRDKyZqHnGKSaZFHvMIIGajCCBVKgAwIBAgIQAwGa
# Ajr/WLFr1tXq5hfwZjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzEVMBMG
# A1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEw
# HwYDVQQDExhEaWdpQ2VydCBBc3N1cmVkIElEIENBLTEwHhcNMTQxMDIyMDAwMDAw
# WhcNMjQxMDIyMDAwMDAwWjBHMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNl
# cnQxJTAjBgNVBAMTHERpZ2lDZXJ0IFRpbWVzdGFtcCBSZXNwb25kZXIwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjZF38fLPggjXg4PbGKuZJdTvMbuBT
# qZ8fZFnmfGt/a4ydVfiS457VWmNbAklQ2YPOb2bu3cuF6V+l+dSHdIhEOxnJ5fWR
# n8YUOawk6qhLLJGJzF4o9GS2ULf1ErNzlgpno75hn67z/RJ4dQ6mWxT9RSOOhkRV
# fRiGBYxVh3lIRvfKDo2n3k5f4qi2LVkCYYhhchhoubh87ubnNC8xd4EwH7s2AY3v
# J+P3mvBMMWSN4+v6GYeofs/sjAw2W3rBerh4x8kGLkYQyI3oBGDbvHN0+k7Y/qpA
# 8bLOcEaD6dpAoVk62RUJV5lWMJPzyWHM0AjMa+xiQpGsAsDvpPCJEY93AgMBAAGj
# ggM1MIIDMTAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8E
# DDAKBggrBgEFBQcDCDCCAb8GA1UdIASCAbYwggGyMIIBoQYJYIZIAYb9bAcBMIIB
# kjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCCAWQG
# CCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMA
# IABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8AbgBzAHQAaQB0AHUAdABlAHMA
# IABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAAdABoAGUAIABEAGkAZwBpAEMA
# ZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkA
# bgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgA
# IABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUA
# IABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5ACAA
# cgBlAGYAZQByAGUAbgBjAGUALjALBglghkgBhv1sAxUwHwYDVR0jBBgwFoAUFQAS
# KxOYspkH7R7for5XDStnAs0wHQYDVR0OBBYEFGFaTSS2STKdSip5GoNL9B6Jwcp9
# MH0GA1UdHwR2MHQwOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydEFzc3VyZWRJRENBLTEuY3JsMDigNqA0hjJodHRwOi8vY3JsNC5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRBc3N1cmVkSURDQS0xLmNybDB3BggrBgEFBQcBAQRrMGkw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcw
# AoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElE
# Q0EtMS5jcnQwDQYJKoZIhvcNAQEFBQADggEBAJ0lfhszTbImgVybhs4jIA+Ah+WI
# //+x1GosMe06FxlxF82pG7xaFjkAneNshORaQPveBgGMN/qbsZ0kfv4gpFetW7ea
# sGAm6mlXIV00Lx9xsIOUGQVrNZAQoHuXx/Y/5+IRQaa9YtnwJz04HShvOlIJ8Oxw
# YtNiS7Dgc6aSwNOOMdgv420XEwbu5AO2FKvzj0OncZ0h3RTKFV2SQdr5D4HRmXQN
# JsQOfxu19aDxxncGKBXp2JPlVRbwuwqrHNtcSCdmyKOLChzlldquxC5ZoGHd2vNt
# omHpigtt7BIYvfdVVEADkitrwlHCCkivsNRu4PQUCjob4489yq9qjXvc2EQwggbN
# MIIFtaADAgECAhAG/fkDlgOt6gAK6z8nu7obMA0GCSqGSIb3DQEBBQUAMGUxCzAJ
# BgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5k
# aWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBD
# QTAeFw0wNjExMTAwMDAwMDBaFw0yMTExMTAwMDAwMDBaMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMTCCASIwDQYJKoZI
# hvcNAQEBBQADggEPADCCAQoCggEBAOiCLZn5ysJClaWAc0Bw0p5WVFypxNJBBo/J
# M/xNRZFcgZ/tLJz4FlnfnrUkFcKYubR3SdyJxArar8tea+2tsHEx6886QAxGTZPs
# i3o2CAOrDDT+GEmC/sfHMUiAfB6iD5IOUMnGh+s2P9gww/+m9/uizW9zI/6sVgWQ
# 8DIhFonGcIj5BZd9o8dD3QLoOz3tsUGj7T++25VIxO4es/K8DCuZ0MZdEkKB4YNu
# gnM/JksUkK5ZZgrEjb7SzgaurYRvSISbT0C58Uzyr5j79s5AXVz2qPEvr+yJIvJr
# GGWxwXOt1/HYzx4KdFxCuGh+t9V3CidWfA9ipD8yFGCV/QcEogkCAwEAAaOCA3ow
# ggN2MA4GA1UdDwEB/wQEAwIBhjA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUH
# AwIGCCsGAQUFBwMDBggrBgEFBQcDBAYIKwYBBQUHAwgwggHSBgNVHSAEggHJMIIB
# xTCCAbQGCmCGSAGG/WwAAQQwggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3LmRp
# Z2ljZXJ0LmNvbS9zc2wtY3BzLXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUHAgIw
# ggFWHoIBUgBBAG4AeQAgAHUAcwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQByAHQA
# aQBmAGkAYwBhAHQAZQAgAGMAbwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBjAGUA
# cAB0AGEAbgBjAGUAIABvAGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAgAEMA
# UAAvAEMAUABTACAAYQBuAGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQAGEA
# cgB0AHkAIABBAGcAcgBlAGUAbQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBtAGkA
# dAAgAGwAaQBhAGIAaQBsAGkAdAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBjAG8A
# cgBwAG8AcgBhAHQAZQBkACAAaABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBlAHIA
# ZQBuAGMAZQAuMAsGCWCGSAGG/WwDFTASBgNVHRMBAf8ECDAGAQH/AgEAMHkGCCsG
# AQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29t
# MEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqg
# OKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3JsMB0GA1UdDgQWBBQVABIrE5iymQftHt+ivlcNK2cCzTAfBgNVHSME
# GDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEARlA+
# ybcoJKc4HbZbKa9Sz1LpMUerVlx71Q0LQbPv7HUfdDjyslxhopyVw1Dkgrkj0bo6
# hnKtOHisdV0XFzRyR4WUVtHruzaEd8wkpfMEGVWp5+Pnq2LN+4stkMLA0rWUvV5P
# sQXSDj0aqRRbpoYxYqioM+SbOafE9c4deHaUJXPkKqvPnHZL7V/CSxbkS3BMAIke
# /MV5vEwSV/5f4R68Al2o/vsHOE8Nxl2RuQ9nRc3Wg+3nkg2NsWmMT/tZ4CMP0qqu
# AHzunEIOz5HXJ7cW7g/DvXwKoO4sCFWFIrjrGBpN/CohrUkxg0eVd3HcsRtLSxwQ
# nHcUwZ1PL1qVCCkQJjGCBDswggQ3AgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAv
# BgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EC
# EANRgwbrGgA18btJ2k5C8GEwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAI
# oAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIB
# CzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHdN+MsRNAoUAfQrjYkV
# DRSQguNuMA0GCSqGSIb3DQEBAQUABIIBABL601Eo+Sq1L0MXD7XMiP5aHK34HYIR
# aJOUOtLacO2YUN0eKlvUXSfq/CBRdAPc5xQfjO/C0RHK5ZGvCiPdvC451u017T/U
# YbpZQlCXn9oaQQPQrFc6S/5FaUPa08iaDHEEnd0DR9a8J2isYmnWRrN2tbLz1rhD
# WpQr1oG/XrvcpBRfdhN+SAQO5/Z+xbKneAu2vwxMXImWWgfl0HqT1ySY6vco8aSk
# W7V0FYWxWsEiaf5/6QrzJXxN3udawMrc2qvaAGsu0DtQYrIXsMiVmgDgGhqP4ARv
# CIaxQs7zYS428p1KUrqua4S3cgyvBOc6Jf4F+RoRbGIw71NrUqLijuqhggIPMIIC
# CwYJKoZIhvcNAQkGMYIB/DCCAfgCAQEwdjBiMQswCQYDVQQGEwJVUzEVMBMGA1UE
# ChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYD
# VQQDExhEaWdpQ2VydCBBc3N1cmVkIElEIENBLTECEAMBmgI6/1ixa9bV6uYX8GYw
# CQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcN
# AQkFMQ8XDTIwMDUwNTExMjA1MVowIwYJKoZIhvcNAQkEMRYEFOhoCQsUGSfyiq3r
# gAc6eHx4eDYDMA0GCSqGSIb3DQEBAQUABIIBAFwgM7DvU3UE2bupHZ59pO9I3VGK
# Hmud7QB2hEs1XxpbnF6wcx4T8C6oYfXMgtiPkINJv69FOZTSvMVutFJ0rNso1jRu
# 5Lw1fsFhS4+wZePbwu0u9qcmH/cwHXTmWPO+MgdcuTz94wi7LSLV+jGvNWD1n4lM
# Rk05pgSjwG2i/N1P6eQL59FkrSTOvrWpaS+Rc57fiDesjqBl0fPs+3QMGeF1N2u0
# vnpZFg0eOduJgcf8LnOZxuKkKguK8h6EjyM1/RbJ0uCLRi8SZ7hs9wKjqRhljO5q
# G2xCfU2C7JdxjA7hgt69dH8ztDr+X4YIUHfuA/tS68mTo/4fEATLlEm3ftM=
# SIG # End signature block
