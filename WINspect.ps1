<# 
                                           Spect
   #              #      # # #     #       # # #
    #            #        #       # #     #
     #     #    #        #       #   #   #
      #	 #  #  #        #       #     # #   
     	#     #       # # #    #       # 
	 
 beta version
 Author : A-mIn3

#>

[Console]::ForegroundColor="White"
[Console]::BackgroundColor="Black"

[System.String]$ScriptDirectoryPath  = Split-Path -Parent $MyInvocation.MyCommand.Definition
[System.String]$SecpolFilePath       = Join-Path $ScriptDirectoryPath "secedit.log"
[System.String]$ReportFilePath       = Join-Path $ScriptDirectoryPath "report-$env:COMPUTERNAME.txt"
[System.String]$ExceptionsFilePath   = Join-Path $ScriptDirectoryPath "exceptions-$env:COMPUTERNAME.txt"

[System.String]$Culture=(Get-Culture).Name

$PSVersion=$PSVersionTable.PSVersion.Major

[Int]$SystemRoleID = $(Get-WmiObject -Class Win32_ComputerSystem).DomainRole



$SystemRoles = @{
    0         =    " Standalone Workstation    " ;
    1         =    " Member Workstation        " ;
    2         =    " Standalone Server         " ;
    3         =    " Member Server             " ;
    4         =    " Backup  Domain Controller " ;
    5         =    " Primary Domain Controller "       
}


$PermissionFlags = @{
    0x1         =     "Read-List";
    0x2         =     "Write-Create";
    0x4         =     "Append-Create Subdirectory";                  	
    0x20         =     "Execute file-Traverse directory";
    0x40         =     "Delete child"
    0x10000         =     "Delete";                     
    0x40000         =     "Write access to DACL";
    0x80000         =     "Write Onwer"
}



$AceTypes = @{ 
    0           =     "Allow";
    1           =     "Deny"
}


Function Initialize-Audit {
    
    Clear-Host
     
    SecEdit.exe /export /cfg $SecpolFilePath /quiet
     
    $Start = Get-Date 
    
    sleep 1 
   
    Write-Host "Starting Audit at", $Start
    "-------------------------------------`n"
   
    sleep 2

    Write-Host "[?] Checking for administrative privileges ..`n" -ForegroundColor Black -BackgroundColor White 

    $IsAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
    If(!$IsAdmin){
            
        Write-Warning  "[-] Some of the operations need administrative privileges.`n"
            
        Write-Warning  "[*] Please run the script using an administrative account.`n"
            
        Read-Host "Type any key to continue .."

        Exit
    }
    
    Write-Host "[?] Checking for Default PowerShell version ..`n" -ForegroundColor Black -BackgroundColor White 
   
    If($PSVersion -lt 2){
       
        Write-Warning  "[!] You have PowerShell v1.0.`n"
        
        Write-Warning  "[!] This script only supports Powershell verion 2 or above.`n"
        
        Read-Host "Type any key to continue .."
        
        Exit  
    }
   
    Write-Host "       [+] ----->  PowerShell v$PSVersion`n" 
  
    Write-Host "[?] Detecting system role ..`n" -ForegroundColor Black -BackgroundColor White 
  
    $SystemRoleID = $(Get-WmiObject -Class Win32_ComputerSystem).DomainRole
    
    If($SystemRoleID -ne 1){
    
        "       [-] This script needs access to the domain. It can only be run on a domain member machine.`n"
           
        Read-Host "Type any key to continue .."
            
        Exit    
    }
    
    Write-Host "       [+] ----->",$SystemRoles[[Int]$SystemRoleID],"`n" 
   
    
    Get-LocalSecurityProducts
    Get-WorldExposedLocalShares 
    Check-LocalMembership
    Check-UACLevel
    Check-Autoruns
    Get-BinaryWritableServices 	   -display
    Get-ConfigurableServices   	   -display
    Get-UnquotedPathServices       -display
    Check-HostedServices           -display
    Check-DLLHijackability     
    Check-UnattendedInstallFiles
    Check-ScheduledTasks
    
    $Fin = Get-Date
    
    "`n[!]Done`n"
    
    "Audit completed in {0} seconds. `n" -f $(New-TimeSpan -Start $Start -End $Fin ).TotalSeconds
    
}


Function Get-LocalSecurityProducts {
      <#    
       .SYNOPSIS		
           Gets Windows Firewall Profile status and checks for installed third party security products.
			
       .DESCRIPTION
           This function operates by examining registry keys specific to the Windows Firewall and by using the 
        Windows Security Center to get information regarding installed security products. 
	            
       .NOTE
           The documentation in the msdn is not very clear regarding the productState property provided by
        the SecurityCenter2 namespace. For this reason, this function only uses available informations that were obtained by testing 
        different security products againt the Windows API. 
                            
       .LINK
           http://neophob.com/2010/03/wmi-query-windows-securitycenter2
     #>


      $FirewallPolicySubkey="HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
               
      Write-Host "`n[?] Checking if Windows Firewall is enabled ..`n"     -ForegroundColor Black -BackgroundColor White 
              
      Write-Host "       [?] Checking Firewall Profiles ..`n" -ForegroundColor Black -BackgroundColor White 
      
    Try {
      		
        If(Test-Path -Path $($FirewallPolicySubkey+"\StandardProfile")) {
              
            $Enabled = $(Get-ItemProperty -Path $($FirewallPolicySubkey+"\StandardProfile") -Name EnableFirewall).EnableFirewall  
              
            If($Enabled -eq 1) {

                $StandardProfile="Enabled"

            } Else {
            
                $StandardProfile="Disabled"

            }
              
            "                   [*] Standard Profile  Firewall     :  {0}.`n" -f $StandardProfile

            } Else{
                    
                Write-Warning  "       [-] Could not find Standard Profile Registry Subkey.`n"
              
            }    
                
            If(Test-Path -Path $($FirewallPolicySubkey+"\PublicProfile")) {
                   
                $Enabled = $(Get-ItemProperty -Path $($FirewallPolicySubkey+"\PublicProfile") -Name EnableFirewall).EnableFirewall  
                           
                If($Enabled -eq 1) {

                    $PublicProfile="Enabled"

                } Else {
                    
                    $PublicProfile="Disabled"

                }
                                        
                "                   [*] Public   Profile  Firewall     :  {0}.`n" -f $PublicProfile

            } Else{      
                   
                Write-Warning "       [-] Could not find Public Profile Registry Subkey.`n"
             
            }

            If(Test-Path -Path $($FirewallPolicySubkey+"\DomainProfile")) {
                     
                $Enabled = (Get-ItemProperty -Path $($FirewallPolicySubkey+"\DomainProfile") -Name EnableFirewall).EnableFirewall  
              
                If($Enabled -eq 1) {

                    $DomainProfile="Enabled"

                } Else {

                    $DomainProfile="Disabled"

                }
              
                "                   [*] Domain   Profile  Firewall     :  {0}.`n`n" -f $DomainProfile

            } Else{
                           
                Write-Warning  "       [-] Could not find Private Profile Registry Subkey.`n`n"          
            }              
                 
    } Catch {

        $ErrorMessage = $_.Exception.Message
            
        $FailedItem = $_.Exception.ItemName

        "[-] Exception : " | Set-Content $ExceptionsFilePath
              
        "[*] Error Message : `n",$ErrorMessage | Set-Content $ExceptionsFilePath
              
        "[*] Failed Item   : `n",$FailedItem   | Set-Content $ExceptionsFilePath
              
        Write-Warning -Message "[-] Error : Could not check Windows Firewall registry informations .`n`n"	
     
      }       
            
      
      $SecurityProvider=@{         
            "00"     =   "None";
            "01"     =   "Firewall";
            "02"     =   "AutoUpdate_Settings";
            "04"     =   "AntiVirus";           
            "08"     =   "AntiSpyware";
            "10"     =   "Internet_Settings";
            "20"     =   "User_Account_Control";
            "40"     =   "Service"
      }
               
               
      $RealTimeBehavior = @{                              
            "00"    =    "Off";
            "01"    =    "Expired";
            "10"    =    "ON";
            "11"    =    "Snoozed"
      }
               
     
      $DefinitionStatus = @{
            "00"     =     "Up-to-date";
            "10"     =     "Out-of-date"
      }
               
      $SecurityCenterNS="root\SecurityCenter"
             
      [System.Version]$OSVersion=(Get-WmiObject -class Win32_operatingsystem).Version
              
      If($OSVersion -gt [System.Version]'6.0.0.0') {
      
            $SecurityCenterNS += "2"
      
      }
              
      # checks for third party firewall products 
 
      Write-Host "`n[?] Checking for third party Firewall products .. `n" -ForegroundColor Black -BackgroundColor White
              
      
      Try {  
            
            $Firewalls= @(Get-WmiObject -Namespace $SecurityCenterNS -Class FirewallProduct)
           
            If($Firewalls.Count -eq 0) {
           
                  "       [-] No other firewall installed.`n"

            } Else {
             
                  "       [+] Found {0} third party firewall products.`n"  -f $($Firewalls.Count)    
            
                  Write-Host "            [?] Checking for product configuration ...`n" -ForegroundColor Black -BackgroundColor White 
            
                  $Firewalls | Foreach-Object {
                          
                        # The structure of the API is different depending on the version of the SecurityCenter Namespace
                        If($SecurityCenterNS.Endswith("2")){
                                            
                              [Int]$ProductState = $_.ProductState
                          
                              $HexString = [System.Convert]::toString($ProductState,16).Padleft(6,'0')
                          	
                              $Provider = $HexString.Substring(0,2)
                          
                              $RealTimeProtec = $HexString.Substring(2,2)
                          
                              $Definition = $HexString.Substring(4,2)
                                         
                              "                     [+] Product Name          : {0}."     -f $_.displayName
                              "                     [+] Service Type          : {0}."     -f $SecurityProvider[[String]$Provider]
                              "                     [+] State                 : {0}.`n`n" -f $RealTimeBehavior[[String]$RealTimeProtec]

                        } Else {
                            
                              "                     [+] Company Name           : {0}."     -f $_.CompanyName
                              "                     [+] Product Name           : {0}."     -f $_.displayName
                              "                     [+] State                  : {0}.`n`n" -f $_.enabled

                        }

                  }
              
            }
            
            sleep 2
  
            # checks for antivirus products

            Write-Host "`n[?] Checking for installed antivirus products ..`n"-ForegroundColor Black -BackgroundColor White 

            $Antivirus=@(Get-WmiObject -Namespace $SecurityCenterNS -Class AntiVirusProduct)
              
            If($Antivirus.Count -eq 0) {
                
                  "       [-] No antivirus product installed.`n`n"      
              
            } Else {
                  "       [+] Found {0} AntiVirus solutions.`n" -f $($Antivirus.Count)
              
                  Write-Host "            [?] Checking for product configuration ..`n" -ForegroundColor Black -BackgroundColor White 
              
                  $Antivirus | Foreach-Object {

                        If($SecurityCenterNS.Endswith("2")){
                                            
                              [Int]$ProductState = $_.ProductState
                                       
                              $HexString = [System.Convert]::toString($ProductState,16).Padleft(6,'0')
                                       
                              $Provider = $HexString.Substring(0,2)
                                       
                              $RealTimeProtec = $HexString.Substring(2,2)
                                       
                              $Definition = $HexString.Substring(4,2)
             
                              "                     [+] Product Name          : {0}."     -f $_.displayName
                              "                     [+] Service Type          : {0}."     -f $SecurityProvider[[String]$Provider]
                              "                     [+] Real Time Protection  : {0}."     -f $RealTimeBehavior[[String]$RealTimeProtec]
                              "                     [+] Signature Definitions : {0}.`n`n" -f $DefinitionStatus[[String]$Definition]
                                                                     
                        } Else {
                            
                              "                     [+] Company Name           : {0}."     -f $_.CompanyName
                              "                     [+] Product Name           : {0}."     -f $_.displayName
                              "                     [+] Real Time Protection   : {0}."     -f $_.onAccessScanningEnabled
                              "                     [+] Product up-to-date     : {0}.`n`n" -f $_.productUpToDate

                        }

                  }
               
                
            }


            # Checks for antispyware products

            Write-Host "`n[?] Checking for installed antispyware products ..`n"-ForegroundColor Black -BackgroundColor White 
            
            $Antispyware = @(Get-WmiObject -Namespace $SecurityCenterNS -Class AntiSpywareProduct)
         
            If($Antispyware.Count -eq 0) {
          
                  "       [-] No antiSpyware product installed.`n`n"     
         
            } Else {
                  
                  "       [+] Found {0} antiSpyware solutions.`n" -f $($AntiSpyware.Count)

                  Write-Host "            [?] Checking for product configuration ..`n" -ForegroundColor Black -BackgroundColor White 
          
                  $Antispyware | Foreach-Object {
                		              
                        If($SecurityCenterNS.Endswith("2")) {
                                            
                              [Int]$ProductState = $_.ProductState
                                         
                              $HexString = [System.Convert]::toString($ProductState,16).PadLeft(6,'0')
                                         
                              $Provider = $HexString.Substring(0,2)
                                         
                              $RealTimeProtec = $HexString.Substring(2,2)
                                         
                              $Definition = $HexString.Substring(4,2)
                                         
                              "                     [+] Product Name          : {0}."     -f $_.displayName
                              "                     [+] Service Type          : {0}."     -f $SecurityProvider[[String]$Provider]
                              "                     [+] Real Time Protection  : {0}."     -f $RealTimeBehavior[[String]$RealTimeProtec]
                              "                     [+] Signature Definitions : {0}.`n`n" -f $DefinitionStatus[[String]$Definition]
                                         
                        } Else {
                            
                              "                     [+] Company Name           : {0}."     -f $_.CompanyName
                              "                     [+] Product Name           : {0}."     -f $_.displayName
                              "                     [+] Real Time Protection   : {0}."     -f $_.onAccessScanningEnabled
                              "                     [+] Product up-to-date     : {0}.`n`n" -f $_.productUpToDate
                            
                        }

                  }

            }

     
      } Catch {
              
            $ErrorMessage = $_.Exception.Message
            
            $FailedItem = $_.Exception.ItemName

            "[-] Exception : " | Set-Content $ExceptionsFilePath
              
            "[*] Error Message : `n",$ErrorMessage | Set-Content $ExceptionsFilePath
              
            "[*] Failed Item   : `n",$FailedItem   | Set-Content $ExceptionsFilePath

      }

}


Function Get-WorldExposedLocalShares {
      <#
       .SYNOPSIS
           Gets informations about local shares and their associated DACLs.

       .DESCRIPTION
           This function checks local file system shares and collects informations about each 
	Access Control Entry (ACE) looking for those targeting the Everyone(Tout le monde) group.
            
       .NOTE
           This function can be modified in a way that for each share we
        return its corresponding ace objects for further processing.

        .LINK
           https://msdn.microsoft.com/en-us/library/windows/desktop/aa374862(v=vs.85).aspx

      #>

    
      $Exists = $False
   
      $Rules = @()

      Write-Host "`n[?] Checking for World-exposed local shares ..`n" -ForegroundColor Black -BackgroundColor White 

      Try {
		  
            Get-WmiObject -Class Win32_share -Filter "type=0" | Foreach-Object {
                  
                $Rules = @()
                   
                $ShareName = $_.Name
                 
                $ShareSecurityObj = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$ShareName'"
                   
                $securityDescriptor = $shareSecurityObj.GetSecurityDescriptor().Descriptor
 
                ForEach($Ace in $SecurityDescriptor.dacl){
 
                      # Looking for Everyone group (SID="S-1-1-0") permissions 
                      $TrusteeSID = (New-Object System.Security.Principal.SecurityIdentifier($Ace.Trustee.SID, 0)).Value.ToString()
                            
                                     
                      If($TrusteeSID -eq "S-1-1-0" -and $AceTypes[[Int]$Ace.aceType] -eq "Allow") {

                            $AccessMask  = $Ace.Accessmask
                            
                            $Permissions = ""
                            
                            Foreach($Flag in $PermissionFlags.Keys) {

                                  If($Flag -band $AccessMask) {
                                          
                                        $Permissions += $PermissionFlags[$Flag]
                                          
                                        $Permissions += "$"
                                  }

                            }

                            $Rule = New-Object PSObject -Property @{
                                  "ShareName"    =  $ShareName     
                                  "Trustee"      =  $Ace.Trustee.Name 
                                  "Permissions"  =  $Permissions
                            }

                            $Rules += $Rule

                            $Exists = $True

                      }
             
                }

                If($Rules.Count -gt 0) {
           
                      "[*]-----------------------------------------------------------------------------[*]"
                               
                      $Rules | Format-List ShareName, Trustee, Permissions
            
                }

          }

          If(!$Exists) {
        
                "       [-] No local World-exposed shares were found .`n`n"
          }
    
      } Catch {
               
            $ErrorMessage = $_.Exception.Message
            
            $FailedItem = $_.Exception.ItemName

            "[-] Exception : " | Set-Content $ExceptionsFilePath
              
            "[*] Error Message : `n",$ErrorMessage | Set-Content $ExceptionsFilePath
              
            "[*] Failed Item   : `n",$FailedItem | Set-Content $ExceptionsFilePath
              
            "[-] Unable to inspect local shares. "
      }

}


$Global:local_member = $False

Function Check-LocalMembership {
     <#
       .SYNOPSIS
           Gets domain users and groups with local group membership.
                        
       .DESCRIPTION
           This function checks local groups on the machine for domain users/groups who are members in a local group.
        It uses ADSI with the WinNT and LDAP providers to access user and group objects.
                  
       .NOTE 
           The machine must be a domain member. This is needed in order to resolve 
	the identity references of domain members.
            
     #>
           
      Try { 
           
            Write-Host "`n[?] Checking for domain users with local group membership ..`n" -ForegroundColor Black -BackgroundColor White 

            $Adsi = [ADSI]"WinNT://$env:COMPUTERNAME"

            $Adsigroups = $Adsi.Children | Where-Object { $_.SchemaClassName -eq "group" }

            $Adsigroups | Foreach-Object {

                  Check-GroupLocalMembership $_
            
            }

            If($Global:local_member -eq $False){

                  "       [-] Found no domain user or group with local group membership."

            }
            
            "`n`n"
   
      } Catch {
          
            $ErrorMessage = $_.Exception.Message
            
            $FailedItem = $_.Exception.ItemName

            "[-] Exception : " | Set-Content $ExceptionsFilePath
              
            '[*] Error Message : `n',$ErrorMessage | Set-Content $ExceptionsFilePath
              
            "[*] Failed Item   : `n",$FailedItem | Set-Content $ExceptionsFilePath
              
         
      }
   
}

Function Check-GroupLocalMembership($Group) {
    <# 
       .SYNOPSIS                                  
            Given a specific  ADSI group object, it checks whether it is a local or domain 
        group and looks fro its members.

       .DESCRIPTION                           
            This function is used by the get-LocalMembership function for inspecting nested
        groups membership.
                         
    #>

      $GroupName = $Group.GetType.Invoke().InvokeMember("Name","GetProperty", $Null, $Group, $Null)
                      
      $GroupMembers = @($Group.Invoke("Members")) 
	  
      $GroupMembers | Foreach-Object {                
                       
            $AdsPath = $_.GetType.Invoke().InvokeMember("ADsPath", "GetProperty", $Null, $_, $Null)
                         
            $SidBytes = $_.GetType.Invoke().InvokeMember("ObjectSID", "GetProperty", $Null, $_, $Null)
           
            $SubjectName = (New-Object System.Security.Principal.SecurityIdentifier($SidBytes,0)).Translate([System.Security.Principal.NTAccount])

            If($_.GetType.Invoke().InvokeMember("class", "GetProperty", $Null, $_, $Null) -eq "group") {

                  # check if we have a local group object                                  
                  If($Adspath -match "/$env:COMPUTERNAME/") {

                        Check-LocalGroupMembership $_

                  } Else {
                        
                        # It is a domain group, no further processing needed                                                                                    
                        Write-Host "          [+] Domain group ",$SubjectName," is a member in the",$GroupName,"local group.`n"

                        $Global:local_member = $True
                                  
                  }


            } Else {

                  # if not a group, then it must be a user
                  If( !($AdsPath -match $env:COMPUTERNAME) ) {

                  Write-Host "          [+] Domain user  ",$SubjectName,"is a member of the",$GroupName,"local group.`n"
                                        
                  $Global:local_member = $True
                                                               
                  }
            }

      }

}

Function Check-UACLevel {
        <#
           .SYNOPSIS
              Checks current configuration of User Account Control.

           .DESCRIPTION
              This functions inspects registry informations related to UAC configuration 
           and checks whether UAC is enabled and which level of operation is used.

       #>
        
      Try {
                  
            Write-Host "`n[?] Checking for UAC configuration ..`n" -ForegroundColor Black -BackgroundColor White
         
            $UACRegValues = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
              
            If([Int]$UACRegValues.EnableLUA -eq 1) {
             
                  "          [+] UAC is enabled.`n"

            } Else {
               
                  "          [-] UAC is disabled.`n"

            }
                             
            Write-Host "            [?]Checking for UAC level ..`n" -ForegroundColor Black -BackgroundColor White 
  
            $consentPrompt = $UACregValues.ConsentPromptBehaviorAdmin
              
            $secureDesktop = $UACregValues.PromptOnSecureDesktop
               
            If( $consentPrompt -eq 0 -and $secureDesktop -eq 0) {
                            
                  "                          [*] UAC Level : Never Notify.`n`n"
          
            } ElseIf($consentPrompt -eq 5 -and $secureDesktop -eq 0) {
                          
                  "                          [*] UAC Level : Notify only when apps try to make changes (No secure desktop).`n`n"
              
            } ElseIf($consentPrompt -eq 5 -and $secureDesktop -eq 1) {
                          
                  "                          [*] UAC Level : Notify only when apps try to make changes (secure desktop on).`n`n"
              
            } ElseIf($consentPrompt -eq 5 -and $secureDesktop -eq 2) {
               
                  "                          [*] UAC Level : Always Notify with secure desktop.`n`n"
            }
         
      } Catch {
         
            $ErrorMessage = $_.Exception.Message
            
            $FailedItem = $_.Exception.ItemName

            "[-] Exception : " | Set-Content $ExceptionsFilePath
              
            '[*] Error Message : `n',$ErrorMessage | Set-Content $ExceptionsFilePath
              
            "[*] Failed Item   : `n",$FailedItem   | Set-Content $ExceptionsFilePath
              
      }

}


Function check-DLLHijackability{ 

      <#
        .SYNOPSIS
            Checks DLL Search mode and inspects permissions for directories in system %PATH%
         and checks write access for Authenticated Users group on these directories.
            
        .DESCRIPTION
            This functions tries to identify if DLL Safe Search is used and inspects 
         write access to directories in the path environment variable .
         It also looks for any DLLs loaded by running processes (#TODO)
               
     #>
        
      Write-Host "`n[?] Checking for DLL hijackability ..`n" -ForegroundColor Black -BackgroundColor White 

      Write-Host "       [?] Checking for Safe DLL Search mode ..`n" -ForegroundColor Black -BackgroundColor White 
       
      Try {
         
            $Value = Get-ItemProperty 'HKLM:\SYSTEM\ControlSet001\Control\Session Manager\' -Name SafeDllSearchMode -ErrorAction SilentlyContinue
                   
            If($Value -and ($Value.SafeDllSearchMode -eq 0)) {
        
                  "                [+] DLL Safe Search is disabled !`n"      
            
            } Else {
                   
                  "                [+] DLL Safe Search is enabled !`n"        
               
            }

            Write-Host "       [?] Checking directories in PATH environment variable ..`n" -ForegroundColor Black -BackgroundColor White
           
            $SystemPath = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).PATH
           
            $SystemPath.split(";") | Foreach-Object {
  
                  $Directory = $_
                 
                  $Writable = $False   

                  # We are inspecting write access for the Authenticated Users group
                 
                  $Sid = "S-1-5-11"
                           
                  $DirAcl = Get-Acl $($Directory.Trim('"'))            		

                  Foreach($Rule in $DirAcl.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier])) {
                 
                        If($Rule.IdentityReference -eq $Sid){
                        
                              $AccessMask = $Rule.FileSystemRights.value__

                              # Here we are checking directory write access in UNIX sense (write/delete/modify permissions)
                              # We use a combination of flags 
                                   
                              If($accessMask -BAND 0xd0046){
                                    
                                    $Writable = $True
                              
                              }

                        }
                          
                  }
              
                  $item = New-Object psobject -Property @{
                               
                        "Directory" = $Directory        
                        "Writable" = $Writable           
                                
                  }

                  $item
              
            } | Format-Table Directory, Writable
              
            "`n`n"
     
      }Catch{
        
            $ErrorMessage = $_.Exception.Message
            
            $FailedItem = $_.Exception.ItemName

            "[-] Exception : " | Set-Content $ExceptionsFilePath
              
            '[*] Error Message : `n',$ErrorMessage | Set-Content $ExceptionsFilePath
              
            "[*] Failed Item   : `n",$FailedItem   | Set-Content $ExceptionsFilePath
        
      }

}

Function Get-BinaryWritableServices {

      param(
            [Switch]$Display
      )
       
      <#
        .SYNOPSIS
           Gets services whose binaries are writable by Authenticated Users group members.
                    
        .DESCRIPTION
           This function checks services that have writable binaries and returns an array 
         containing service objects.
                
        .RETURNS
           When invoked without the $display switch, returns a hashtable of {name : pathname}
        couples.
         
     #>
        


      [Array]$WritableServices = @()

      # Services to be ignored are those in system32 subtree
      $Services = Get-WmiObject -Class Win32_Service | Where-Object { $_.pathname -ne $Null -and $_.pathname -NotMatch ".*system32.*" }
         
      Write-Host "`n[?] Checking for binary-writable services ..`n" -ForegroundColor Black -BackgroundColor White
         
      Try {
     
            If($Services) {
	 	
                  $Services | Foreach-Object { 

                        # We are inspecting write access for Authenticated Users group members (SID = "S-1-5-11") 	
                
                        $Sid = "S-1-5-11"
                 
                        $Pathname = $($_.pathname.subString(0, $_.pathname.toLower().IndexOf(".exe")+4)).Trim('"')
                            
                        $BinaryAcl = Get-Acl $Pathname           		

                        Foreach($Rule in $BinaryAcl.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier])){
                 
                              If($Rule.IdentityReference -eq $Sid) {

                                    $accessMask = $rule.FileSystemRights.value__
                        
                                    If($accessMask -band 0xd0006){
                                    
                                    $writableServices+=$_
                              
                                    }
                        
                              }
                  
                        }
                       
                  }

            }
         

            If($Display) {

                  If($WritableServices.Count -gt 0) {

                        $WritableServices | Format-Table @{Expression={$_.name};Label="Name";width=12}, `
                                                         @{Expression={$_.pathname};Label="Path"}
                
                  } Else {

                        "       [-] Found no binary-writable service."
                  }

            } Else {

                  Return $WritableServices

            }
        
            "`n`n"

      } Catch {
        
            $ErrorMessage = $_.Exception.Message
            
            $FailedItem = $_.Exception.ItemName

            "[-] Exception : " | Set-Content $ExceptionsFilePath
              
            '[*] Error Message : `n',$ErrorMessage | Set-Content $ExceptionsFilePath
              
            "[*] Failed Item   : `n",$FailedItem | Set-Content $ExceptionsFilePath
                      
      }
      
}

Function Get-UnquotedPathServices {
      Param(
            [Switch]$Display
      )
   
   <#
    .SYNOPSIS
        Looks for services with unquoted path vulnerability .

    .DESCRIPTION
        This function gets all non-system32 services with unquotted pathnames.
     If display switch is used, it displays the name, state, start mode and pathname information,            
     otherwise it returns a array of the vulnerable services.
	      
    .RETURNS
       When invoked without the $display switch, returns a hashtable of {name: pathname}
    couples.
     
   #>

      Write-Host "`n[?] Checking for unquoted path services ..`n" -ForegroundColor Black -BackgroundColor White 

      Try {
      
            [Array]$Services = Get-WmiObject -Class Win32_Service | Where-Object {

                  $_.pathname.Trim() -ne "" -and
                                                    
                  $_.pathname.Trim() -notmatch '^"' -and
                                                
                  $_.pathname.subString(0, $_.pathname.IndexOf(".exe")+4) -match ".* .*"

            }


            If($Display) {

                  If($Services.Count -gt 0) {
                             
                        $services | Format-Table @{Expression={$_.name};Label="Name";width=12}, `
                           
                                                 @{Expression={$_.state};Label="Sate";width=12}, `
                           
                                                 @{Expression={$_.StartMode};Label="Start Mode";width=12}, `
                           
                                                 @{Expression={$_.pathname};Label="Path"} ;
                               
                        ""

                  } Else {

                        "          [-] Found no service with unquoted pathname."
                  
                  }

                  "`n`n"
       
            } Else {
              
                  Return $Services
       
            }

      }Catch{
           
            $ErrorMessage = $_.Exception.Message
            
            $FailedItem = $_.Exception.ItemName

            "[-] Exception : " | Set-Content $ExceptionsFilePath
              
            '[*] Error Message : `n',$ErrorMessage | Set-Content $ExceptionsFilePath
              
            "[*] Failed Item   : `n",$FailedItem | Set-Content $ExceptionsFilePath
                                 
      }

}

Function Get-ConfigurableServices {

      Param(
            [Switch]$Display
      )

      <#
           .SYNOPSYS
                Gets all services that the current user can configure

           .DESCRIPTION
                This function tries to enumerate services for which configuration
             properties can be modified by the Authenticated Users group members.
             It uses the sc utility with the sdshow command to inspect the security 
             descriptor of the service object.
                             

           .RETURNS
                When invoked without the $display switch, returns a hashtable of {name: pathname}
             couples.

      #>

            
      $Configurable = @{} 
            
      Write-Host "`n[?] Checking for configurable services ..`n" -ForegroundColor Black -BackgroundColor White 
     
      Try {       
           
            Get-WmiObject -Class Win32_Service | Where-Object { $_.pathname -notmatch ".*system32.*" } | Foreach-Object {

                  # get the security descriptor of the service in SDDL format
                  
                  $Sddl = [String]$(sc.exe sdshow $($_.Name))
                  
                  If($Sddl -match "S:") {
                       
                        $Dacl = $Sddl.SubString(0,$sddl.IndexOf("S:"))
                  
                  } Else {
                       
                        $Dacl = $Sddl          
                  
                  }
                
                  # We are interested in permissions related to Authenticated Users group which is assigned
                  # a well known alias ("AU") in the security descriptor sddl string.
        
                  $Permissions = [Regex]::match($Dacl, '\(A;;[A-Z]+;;;AU\)')

                  If($Permissions) {
                  
                        If($Permissions.Value.Split(';')[2] -match "CR|RP|WP|DT|DC|SD|WD|WO") {

                              $Configurable[$_.Name] = $($_.PathName.SubString(0, $_.PathName.toLower().IndexOf(".exe")+4)).Trim('"')
 
                        }
                  
                  }
            
            }

            If($Display) {
                  
                  If($Configurable.Count -gt 0) {

                        $Configurable.GetEnumerator() | Format-Table @{Expression={$_.name};Label="Name"}, `
                                                                     @{Expression={$_.value};Label="Path"} ;

                  } Else {
                                   
                        "       [-] Found no configurable services."

                  }

                  "`n`n"
            
            } Else {

                  Return $Configurable

            }

       
      } Catch {
       
                 
            $ErrorMessage = $_.Exception.Message
            
            $FailedItem = $_.Exception.ItemName

            "[-] Exception : " | Set-Content $ExceptionsFilePath
              
            '[*] Error Message : `n',$ErrorMessage | Set-Content $ExceptionsFilePath
              
            "[*] Failed Item   : `n",$FailedItem | Set-Content $ExceptionsFilePath
                    
       }
 
}
       
Function Check-HostedServices {
  
      Param(
            [Switch]$display
      )
      <#
          .SYNOPSIS
               Checks hosted services running DLLs not located in the system32 subtree.

          .DESCRIPTION
               This functions tries to identify whether there are any configured hosted 
           services based on DLLs not in system32.
                
          .RETURNS
               When invoked without the $display switch, returns 
           PSobject array containing the service name, service groupname 
           and the service DLL path. 
        
     #>
       
       
      $Exits = $False
       
      $Svcs = @()
     
      Try {   
       
            $Services = Get-WmiObject -Class Win32_service | Where-Object { $_.pathname -match "svchost\.exe" -and $(Test-Path $("HKLM:\SYSTEM\CurrentControlSet\Services\"+$_.Name+"\Parameters")) -eq $True }
        
            Write-Host "`n[?] Checking hosted services (svchost.exe) ..`n" -ForegroundColor Black -BackgroundColor White 
       
            If($Services) {
        
                  Foreach($Service in $Services) {
                
                        $ServiceName  = $Service.Name 
              
                        $ServiceGroup = $Service.PathName.Split(" ")[2]
                   
                        $ServiceDLLPath=$(Get-ItemProperty $("HKLM:\SYSTEM\CurrentControlSet\Services\"+$service.Name+"\Parameters") -Name ServiceDLL).ServiceDLL
                        
                        If($serviceDLLPath -ne $Null -and $serviceDLLPath -NotMatch ".*system32.*") { 
                              
                              $svcs += New-Object PSObject -Property @{
                            
                                    serviceName    = $serviceName
                                    serviceGroup   = $serviceGroup
                                    serviceDLLPath = $serviceDLLPath
                        
                              }
                       
                              $Exits = $True
                       
                        }
               
                  }

            If($Display) {   
                         
                  $svcs | Format-Table *
      
                  "`n`n"

            } Else {
                  
                  Return $svcs
                
            }
                
      }
        
      If(! $Exits) {
        
            "          [-] Found no user hosted services.`n"
                   
      }
     
      } Catch {
             
      $ErrorMessage = $_.Exception.Message
            
      $FailedItem = $_.Exception.ItemName

      "[-] Exception : " | Set-Content $ExceptionsFilePath
              
      '[*] Error Message : `n',$ErrorMessage | Set-Content $ExceptionsFilePath
              
      "[*] Failed Item   : `n",$FailedItem | Set-Content $ExceptionsFilePath
               
   }
  
}

Function Check-Autoruns {

       <#
         .SYNOPSIS
              Looks for autoruns specified in different places in the registry.
                         
         .DESCRIPTION
              This function inspects common registry keys used for autoruns.
          It examines the properties of these keys and report any found executables along with their pathnames.
                  
       #>

    
      $RegistryKeys = @( 

            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
            "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\load",
            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
            "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"   # DLLs specified in this entry can hijack any process that uses user32.dll 
                            
            # not sure if it is all we need to check!
      )


         
      $Exits = $False

      Write-Host "`n[?] Checking registry keys for autoruns ..`n" -ForegroundColor Black -BackgroundColor White 

      Try {
         
            $RegistryKeys | Foreach-Object {

                  $Key = $_

                  If(Test-Path -Path $Key) {

                        $Executables = @{}

                        [Array]$Properties = Get-Item $Key | Select-Object -ExpandProperty Property

                        If($Properties.Count -gt 0) {

                              "          [*] $Key : "

                              Foreach($Exe in $Properties) {

                                    $Executables[$Exe]=$($($(Get-ItemProperty $Key).$Exe)).Replace('"','')

                              }

                              $Executables | Format-Table @{Expression={$_.Name};Label="Executable"}, `
                                                          @{Expression={$_.Value};Label="Path"}

                              $Exits = $True

                        }

                  }

            }


            If($Exits -eq $False){

                  "          [-] Found no autoruns ."
             
            }

            "`n`n"
      
      } Catch {
              
            $ErrorMessage = $_.Exception.Message
            
            $FailedItem = $_.Exception.ItemName

            "[-] Exception : " | Set-Content $ExceptionsFilePath
              
            '[*] Error Message : `n',$ErrorMessage | Set-Content $ExceptionsFilePath
              
            "[*] Failed Item   : `n",$FailedItem | Set-Content $ExceptionsFilePath
      
      }
 
 }
 
 
 Function Check-UnattendedInstallFiles{

      <#  
	     .SYNOPSIS
              Checks for remaining files used by unattended installs .

         .DESCRIPTION
              This functions checks for remaining files used during Windows deployment
	      by searching for specific files .
  
      #>

      $Found = $False

      $TargetFiles = @(

            "C:\unattended.xml",
            "C:\Windows\Panther\unattend.xml",
            "C:\Windows\Panther\Unattend\Unattend.xml",
            "C:\Windows\System32\sysprep.inf",
            "C:\Windows\System32\sysprep\sysprep.xml"

        )

      Write-Host "[?] Checking for unattended install leftovers ..`n" -ForegroundColor Black -BackgroundColor White 

      Try{
       
            $TargetFiles | Where-Object { $(Test-Path $_) -eq $True} | Foreach-Object {
	           
                  $Found = $True;
                  "          [+] Found : $_"
            
            }
              
            If(!$Found) {

                  "             [-] No unattended install files were found.`n"
                
            }
      
            "`n"

      } Catch {
                    
            $ErrorMessage = $_.Exception.Message
            
            $FailedItem = $_.Exception.ItemName
  
            "[-] Exception : " | Set-Content $ExceptionsFilePath
              
            '[*] Error Message : `n',$ErrorMessage | Set-Content $ExceptionsFilePath
              
            "[*] Failed Item   : `n",$FailedItem | Set-Content $ExceptionsFilePath
                     
      }

}

Function Check-ScheduledTasks {

       <#
	     .SYNOPSIS
             Checks for scheduled tasks whose binaries are not in *.system32.*
   
         .DESCRIPTION
             This function looks for scheduled tasks invoking non-system executables.

         .NOTE
             This function uses the schtasks.exe utility to get informations about
          scheduled task and then tries to parse the results. Here I choose to parse XML output from the command.
          Another approach would be using the ScheduledTask Powershell module that was introduced starting from version 3.0 .

       #>

        
      $Found=$False

      Write-Host "[?] Checking scheduled tasks.." -ForegroundColor Black -BackgroundColor White
         
      Try {

            [XML]$TasksXMLObj = $(schtasks.exe /query /xml ONE)

            $TasksXMLObj.Tasks.Task | Foreach-Object {

                  $TaskCommandPath = [System.Environment]::ExpandEnvironmentVariables($_.actions.exec.command).Trim()

                  If($TaskCommandPath -ne $Null -and $TaskCommandPath -NotMatch ".*system32.*") {

                        $Sid = New-Object System.Security.Principal.SecurityIdentifier($_.Principals.Principal.UserID)

                        $TaskSecurityContext = $Sid.Translate([System.Security.Principal.NTAccount])

                        $Task = New-Object PSObject -Property @{

                              TaskCommand = $TaskCommandPath

                              SecurityContext  = $TaskSecurityContext

                        }

                        $Found = $True

                        $Task
      
                  }

            } | Format-List taskCommand, SecurityContext

            If($Found -eq $False) {
      
                  "         [-] No suspicious scheduled tasks were found.`n`n"
            }
       
      } Catch{            
                
            $ErrorMessage = $_.Exception.Message
            
            $FailedItem = $_.Exception.ItemName
           
            "[-] Exception : " | Set-Content $ExceptionsFilePath
              
            '[*] Error Message : `n',$ErrorMessage | Set-Content $ExceptionsFilePath
              
            "[*] Failed Item   : `n",$FailedItem | Set-Content $ExceptionsFilePath    
         
      }

}

Initialize-Audit