function Get-ActiveUsersAudit {
    <#
    .SYNOPSIS
        Active Directory Audit with Keyvault retrieval option.
    .DESCRIPTION
        Audit's Active Directory taking "days" as the input for how far back to check for a last sign in. 
    .EXAMPLE
        PS C:\> Get-ActiveUsersAudit -UserName "helpdesk@domain.com" -Uri "https://<instance>.azurewebsites.net/api/HttpTrigger1?code=<Personal URL CODE>&clientId=<FunctionHTMLName>" -To "support@domain.com" -From "helpdesk@domain.com" -AttachementFolderPath "C:\temp" -DaysInactive 90 -Verbose
    .EXAMPLE
        PS C:\> Get-ActiveUsersAudit -UserName "helpdesk@domain.com" -Password "<Clear-Text String>" -To "support@domain.com" -From "helpdesk@domain.com" -AttachementFolderPath "C:\temp" -DaysInactive 90 -Verbose
    .PARAMETER UserName
        Specify the account with an active mailbox and MFA disabled. 
        Ensure the account has delegated access for Send On Behalf for any 
        UPN set in the "$From" Parameter
    .PARAMETER Uri
        Function App URL for specific customer or department needing access to the key.
    .PARAMETER Password
        Use this parameter to active the parameterset associated with using a clear-text
        password instead of a function URI.
    .PARAMETER To
        Recipient of the attachment outputs. 
    .PARAMETER From
        Defaults to the same account as $UserName unless the parameter is set.  
        The email will appear as it was sent from the UPN listed here. 
        Ensure the Account stated in the $UserName has delegated access to send
        on behalf of the account you add to the $From parameter. 
    .PARAMETER AttachementFolderPath
        Default path is C:\temp\ActiveUserAuditLogs.
        This is the folder where attachments are going to be saved.
    .PARAMETER DaysInactive
        Defaults to 90 days in the past. 
        Specifies how far back to look for accounts last logon. 
        If logon is within 90 days, it won't be included. 
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Output (if any)
    .NOTES
        Can take password as input into secure string instead of URI. 
        Adding the password parameter right after username when calling the function will trigger the correct parameterset. 
    #>
    [CmdletBinding()]
    param (
        [Parameter(
            Position = '0',
            Mandatory = $true,
            HelpMessage = "UPN as in user@contoso.com",
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]
        $UserName,
        [Parameter(
            Position = '1',
            ParameterSetName = 'URL Key Vault',
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$Uri,
        [Parameter(
            Position = '1',
            ParameterSetName = 'Password',
            ValueFromPipelineByPropertyName = $true
        )]
        [securestring]$Password,
        [Parameter(
            Position = '2',
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$SMTPServer = "smtp.office365.com",        
        [Parameter(
            Position = '3',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$To,
        [Parameter(
            Position = '4',
            HelpMessage = "Defaults to Username",
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$From = $UserName,
        [Parameter(
            Position = '5',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$AttachementFolderPath = "C:\temp\ActiveUserAuditLogs",
        [Parameter(
            Position = '6',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$DaysInactive = "90"
    )
    Begin {
        # Check for admin and throw exception if not running elevated.
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (!($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
            throw "Not Running as admin! Please rerun as administrator!"
        }
        # Set TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # Create Log Path
        $DirPath = "C:\temp\ActiveUserAuditLogs"
        $DirPathCheck = Test-Path -Path $DirPath
        If (!($DirPathCheck)) {
            Try {
                #If not present then create the dir
                New-Item -ItemType Directory $DirPath -Force
            }
            Catch {
                throw "Directory: $DirPath was not created."
            }
        }
        # Begin Logging
        Start-Transcript -OutputDirectory $DirPath -IncludeInvocationHeader -NoClobber

        # Install / Import required modules.
        $module = Get-Module -Name Send-MailKitMessage -ListAvailable
        if (-not $module) {
            Install-Module -Name Send-MailKitMessage -AllowPrerelease -Scope AllUsers -Force
        }
        try {
            Import-Module "Send-MailKitMessage" -Global
        }
        catch {
            throw "The Module Was not installed. Use `"Save-Module -Name Send-MailKitMessage -AllowPrerelease -Path C:\temp`" on another Windows Machine."
        }
    }

    Process {
        # Create CSV Path Prefix
        $csvPath = "$attachementfolderpath\AD_Export_$($env:USERDNSDOMAIN)"
        
        # Establish timeframe to review.  
        $time = (Get-Date).Adddays( - ($DaysInactive))

        # Add Datetime to filename
        $csv = "$($csvPath).$((Get-Date).ToString('yyyy-MM-dd.hh.mm'))" 
    
        # Audit Script with export to csv and zip. Paramters for Manager, lastLogonTimestamp and DistinguishedName normalized.
        Get-aduser -Filter { LastLogonTimeStamp -lt $time -and Enabled -eq $true } -Properties `
            GivenName, Surname, Mail, UserPrincipalName, Title, OfficePhone, MobilePhone, Description, Manager, lastlogontimestamp, samaccountname, DistinguishedName   | `
            Select-Object `
        @{N = 'FirstName'; E = { $_.GivenName } }, `
        @{N = 'LastName'; E = { $_.Surname } }, `
        @{N = 'UserName'; E = { $_.samaccountname } }, `
        @{N = 'SMTP PrimaryEmail'; E = { $_.mail } }, `
        @{N = 'UPN'; E = { $_.UserPrincipalName } }, `
        @{N = 'Job Title'; E = { $_.Title } }, `
        @{N = 'Telephone'; E = { $_.OfficePhone } }, `
        @{N = 'MobilePhone'; E = { $_.MobilePhone } }, `
        @{N = 'NoteEquipment'; E = { $_.Description } }, `
        @{N = 'Manager'; E = { (Get-ADUser ($_.Manager)).name } }, `
        @{N = "Stamp"; E = { [DateTime]::FromFileTime($_.lastLogonTimestamp).ToString('yyyy-MM-dd.hh.mm') } }, `
        @{N = 'OrgUnit'; E = { $($_.DistinguishedName.split(',', 2)[1]) } } `
        | Export-CSV -Path "$csv.csv" -NoTypeInformation
        Compress-Archive -Path "$csv.csv" -DestinationPath "$csv.zip"
    }
    End {
        if ($Password) {
            <# 
            Send Attachement using O365 email account and password. 
            Must exclude from conditional access legacy authentication policies.
            #> 
            Send-AuditEmail -smtpServer $SMTPServer -port "587" -username $Username `
                -pass $Password -from $from -to $to -attachmentfilePath "$csv.zip" -ssl
        }
        else {
            <#
        Send Attachement using O365 email account and Keyvault retrived password. 
        Must exclude email account from conditional access legacy authentication policies. 
        #>
            Send-AuditEmail -smtpServer $SMTPServer -port "587" -username $Username `
                -url $uri -from $from -to $to -attachmentfilePath "$csv.zip" -ssl
        }
        # Uninstall Installed Modules
        Remove-Module -Name "Send-MailKitMessage" -Force -Confirm:$false
        # Need to correct logic to uninstall module. 
        Uninstall-Module -Name "Send-MailKitMessage" -AllowPrerelease -Force -Confirm:$false
        # End Logging
        Stop-Transcript
    }
}

function Send-AuditEmail {
    param (
        [string]$smtpServer,
        [int]$port,
        [string]$username,
        [switch]$ssl,
        [string]$url,
        [string]$from,
        [string]$to,
        [string]$subject = "Active User Audit for $($env:USERDNSDOMAIN)",
        [string]$attachmentfilePath,
        [string]$body = "Audit done on $(Get-Date). Attachment file: $attachmentfilePath",
        [securestring]$pass
    )
    Import-Module Send-MailKitMessage
    # Recipient
    $RecipientList = [MimeKit.InternetAddressList]::new()
    $RecipientList.Add([MimeKit.InternetAddress]$to)
    # Attachment
    $AttachmentList = [System.Collections.Generic.List[string]]::new()
    $AttachmentList.Add("$attachmentfilePath")
    # From
    $from = [MimeKit.MailboxAddress]$from
    # Mail Account variable
    $User = $usernam
    if ($pass) {
        # Set Credential to $Password parameter input. 
        $Credential = $pass
    }
    else {
        # Retrieve credentials from function app url into a SecureString.
        $Credential = `
            [System.Management.Automation.PSCredential]::new($User, (ConvertTo-SecureString -String "$(Invoke-RestMethod -Uri $url)" -AsPlainText -Force))
    }
    
    # Create Parameter hashtable
    $Parameters = @{
        "UseSecureConnectionIfAvailable" = $ssl
        "Credential"                     = $Credential
        "SMTPServer"                     = $SMTPServer
        "Port"                           = $Port
        "From"                           = $From
        "RecipientList"                  = $RecipientList
        "Subject"                        = $subject
        "TextBody"                       = $body
        "AttachmentList"                 = $AttachmentList
    }
    Send-MailKitMessage @Parameters
}
