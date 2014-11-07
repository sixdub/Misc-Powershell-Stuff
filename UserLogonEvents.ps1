function Get-UserLogonEvents {
<#
.SYNOPSIS
Dump and parse security events relating to an account logon (ID 4624). 
.DESCRIPTION
Provides information about all users who have logged on and where they logged on from. Intended to be used and tested on Windows 2008 Domain Controllers. 
Admin Reqd? YES
.PARAMETER CompName
The computer to get events from. Default: Localhost
.PARAMETER DateStart
Filter out all events before this date. Default: 5 days
#>
	Param(
	[Parameter(Mandatory=$False, Position=1)]
	[string] $CompName=$env:computername,
	[Parameter(Mandatory=$False, Position=2)]
	[DateTime] $DateStart=[DateTime]::Today.AddDays(-5)
	)
    
    #initialize a structure for the output of our function
	$results = @()

    #grab all events matching our filter
	$loginevents = Get-WinEvent -ComputerName $CompName -FilterHashTable @{ LogName = "Security"; ID=4624; StartTime=$datestart}

    #parse each event    
	foreach ($e in $loginevents){
		$username=""
		$addr=""
		$etime=$e.TimeCreated
        
        #first parse and check the logon type. This could be later adapted and tested for RDP logons (type 10)
		if($e.message -match '(?s)(?<=Logon Type:).*?(?=New Logon:)'){
			foreach($match in $Matches){
				$logontype=$match[0].trim()
			}
		}

		#interactive logons or domain logins
		if ($logontype -eq 2 -or $logontype -eq 3){
            #parse and store the account used and the address they came from
			if($e.message -match '(?s)(?<=New Logon:).*?(?=Process Information:)'){
				foreach($match in $Matches){
					$account=$match[0].split("`n")[2].split(":")[1].trim()
				}
			}
			if($e.message -match '(?s)(?<=Network Information:).*?(?=Source Port:)'){
				foreach($match in $Matches){
					$addr=$match[0].split("`n")[2].split(":")[1].trim()
				}
			}
            
			#only add if there was account information
			if ($account -ne "")
			{
				$out = New-Object psobject 
				$out | Add-Member NoteProperty 'Username' $account
				$out | Add-Member NoteProperty 'Address' $addr 
				$out | Add-Member NoteProperty 'Time' $etime
				$results+=$out	
			}
		}
	}

	return $results
}
