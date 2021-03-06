function Get-ActiveUsersAudit {
    <#
    .SYNOPSIS
        Active Directory Audit with Keyvault retrieval option.
    .DESCRIPTION
        Audit's Active Directory taking "days" as the input for how far back to check for a last sign in.
    .EXAMPLE
        PS C:\> Get-ActiveUsersAudit -Verbose
    .EXAMPLE
        PS C:\> Get-ActiveUsersAudit -SendMailMessage -FunctionApp "<FunctionAppName>" -Function "<HttpTriggerName>" -ApiToken "<ApiKey>" -UserName "helpdesk@domain.com" -To "support@domain.com" -Verbose
    .EXAMPLE
        PS C:\> Get-ActiveUsersAudit -SendMailMessage -UserName "helpdesk@domain.com" -Password "Password" -To "support@domain.com" -Verbose
    .PARAMETER UserName
        Specify the account with an active mailbox and MFA disabled.
        Ensure the account has delegated access for Send On Behalf for any
        UPN set in the "$From" Parameter
    .PARAMETER FunctionApp
        Azure Function App Name.
    .PARAMETER Function
        Azure Function App's Function Name. Ex. "HttpTrigger1"
    .PARAMETER ApiToken
        Private Function Key
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
    .PARAMETER Enabled
        Choose to search for either enabled or disabled Active Directory Users (IE: $true or $false)
    .PARAMETER SMTPServer
        Defaults to Office 365 SMTP relay. Enter optional relay here.
    .PARAMETER Port
        SMTP Port to Relay
    .PARAMETER Clean
        Remove installed modules during run.
    .PARAMETER SendMailMessage
        Adds parameters for sending Audit Report as an Email.
    .NOTES
        Can take password as input into secure string instead of URI.
        Adding the password parameter right after username when calling the function will trigger the correct parameterset.
        #>
    [CmdletBinding(DefaultParameterSetName = 'Local', HelpURI = "https://activeusersaudit.criticalsolutions.net/")]
    param (
        [Parameter( Position = '0', ParameterSetName = 'URL Key Vault')]
        [Parameter( Position = '0', ParameterSetName = 'Password')]
        [Parameter(
            Position = '0',
            ParameterSetName = 'Local',
            HelpMessage = 'Enter output folder path',
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$AttachementFolderPath = "C:\temp\ActiveUserAuditLogs",
        [Parameter( Position = '1', ParameterSetName = 'URL Key Vault')]
        [Parameter( Position = '1', ParameterSetName = 'Password')]
        [Parameter(
            Position = '1',
            ParameterSetName = 'Local',
            HelpMessage = "Active Directory User Enabled or not",
            ValueFromPipelineByPropertyName = $true
        )]
        [bool]$Enabled = $true,
        [Parameter( Position = '2', ParameterSetName = 'URL Key Vault')]
        [Parameter( Position = '2', ParameterSetName = 'Password')]
        [Parameter(
            Position = '2',
            HelpMessage = 'Days back to check for recent sign in',
            ValueFromPipelineByPropertyName = $true
        )]
        [int]$DaysInactive = "90",
        [Parameter(Mandatory = $true, Position = '3', ParameterSetName = 'URL Key Vault')]
        [Parameter(Mandatory = $true, Position = '3', ParameterSetName = 'Password')]
        [Parameter(
            Position = '3',
            ParameterSetName = 'Local',
            HelpMessage = "Activate Mail Parameters",
            ValueFromPipelineByPropertyName = $true
        )]
        [switch]$SendMailMessage,
        [Parameter(
            Position = '4',
            Mandatory = $true,
            ParameterSetName = 'Password',
            ValueFromPipelineByPropertyName = $true
        )]
        [securestring]$Password,
        [Parameter(
            Position = '4',
            Mandatory = $true,
            ParameterSetName = 'URL Key Vault',
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$FunctionApp,
        [Parameter(
            Position = '5',
            Mandatory = $true,
            ParameterSetName = 'URL Key Vault',
            ValueFromPipelineByPropertyName = $true
        )][string]$Function,
        [Parameter(
            Position = '6',
            Mandatory = $true,
            ParameterSetName = 'URL Key Vault',
            ValueFromPipelineByPropertyName = $true
        )][string]$ApiToken,
        [Parameter(Mandatory = $true, Position = '7', ParameterSetName = 'URL Key Vault')]
        [Parameter(
            Position = '5',
            Mandatory = $true,
            ParameterSetName = 'Password',
            HelpMessage = "UPN as in user@contoso.com",
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidatePattern("[a-z0-9!#\$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#\$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")]
        [string]$UserName,
        [Parameter(Position = '8', ParameterSetName = 'URL Key Vault')]
        [Parameter(
            Position = '6',
            ParameterSetName = 'Password',
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$SMTPServer = "smtp.office365.com",
        [Parameter(Position = '9', ParameterSetName = 'URL Key Vault')]
        [Parameter(
            Position = '7',
            ParameterSetName = 'Password',
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateSet("993", "587", "25")]
        [int]$Port = "587",
        [Parameter(Position = '10', Mandatory = $true, ParameterSetName = 'URL Key Vault')]
        [Parameter(
            Position = '8',
            Mandatory = $true,
            ParameterSetName = 'Password',
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidatePattern("[a-z0-9!#\$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#\$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")]
        [string]$To,
        [Parameter(Position = '11', ParameterSetName = 'URL Key Vault')]
        [Parameter(
            Position = '9',
            HelpMessage = "Defaults to Username",
            ParameterSetName = 'Password',
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidatePattern("[a-z0-9!#\$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#\$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")]
        [string]$From = $UserName,
        [Parameter(
            HelpMessage = "Cleans up modules",
            ValueFromPipelineByPropertyName = $true
        )]
        [switch]$Clean
    )
    Begin {
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
        if ($SendMailMessage) {
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
    }
    Process {
        # Create CSV Path Prefix
        $csvPath = "$attachementfolderpath\AD_Export_$($env:USERDNSDOMAIN)"
        # Establish timeframe to review.
        $time = (Get-Date).Adddays( - ($DaysInactive))
        # Add Datetime to filename
        $csv = "$($csvPath).$((Get-Date).ToString('yyyy-MM-dd.hh.mm.ss'))"
        Write-Output "Searching for users where Enabled = $Enabled"
        # Audit Script with export to csv and zip. Paramters for Manager, lastLogonTimestamp and DistinguishedName normalized.
        Get-aduser -Filter { LastLogonTimeStamp -lt $time -and Enabled -eq $Enabled } -Properties `
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
        @{N = "Last Sign-in"; E = { [DateTime]::FromFileTime($_.lastLogonTimestamp).ToString('yyyy-MM-dd.hh.mm') } }, `
        @{N = 'OrgUnit'; E = { $($_.DistinguishedName.split(',', 2)[1]) } } `
        | Export-CSV -Path "$csv.csv" -NoTypeInformation
        Compress-Archive -Path "$csv.csv" -DestinationPath "$csv.zip"
        #Confirm output path to console.
        Write-Output "The archive have been saved to: `n"
        Write-Output "$csv.zip"
    }
    End {
        if ($SendMailMessage) {
            if ($Password) {
                <#
                Send Attachement using O365 email account and password.
                Must exclude from conditional access legacy authentication policies.
                #>
                Send-AuditEmail -smtpServer $SMTPServer -port $Port -username $Username `
                    -pass $Password -from $from -to $to -attachmentfilePath "$csv.zip" -ssl
            } # End if
            else {
                <#
                Send Attachement using O365 email account and Keyvault retrived password.
                Must exclude email account from conditional access legacy authentication policies.
                #>
                Send-AuditEmail -smtpServer $SMTPServer -port $Port -username $Username `
                    -Function $Function -FunctionApp $FunctionApp -token $ApiToken -from $from -to $to -attachmentfilePath "$csv.zip" -ssl
            }   # End Else
        }

        if ($Clean) {
            try {
                # Remove Modules
                Remove-Module -Name "Send-MailKitMessage" -Force -Confirm:$false `
                    -ErrorAction SilentlyContinue -ErrorVariable RemoveModErr
            }
            catch {
                Write-Output $RemoveModErr -Verbose
            }
            try {
                # Uninstall Modules
                Uninstall-Module -Name "Send-MailKitMessage" -AllowPrerelease -Force -Confirm:$false `
                    -ErrorAction SilentlyContinue -ErrorVariable UninstallModErr
            }
            catch {
                Write-Output $UninstallModErr -Verbose
            }
        }
        Clear-Variable -Name "Function", "FunctionApp", "Password", "ApiToken" -Scope Local -ErrorAction SilentlyContinue
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
        [string]$from,
        [string]$to,
        [string]$subject = "Active User Audit for $($env:USERDNSDOMAIN)",
        [string]$attachmentfilePath,
        [string]$body = "Audit done on $(Get-Date). Attachment file: $attachmentfilePath",
        [securestring]$pass,
        [string]$Function,
        [string]$FunctionApp,
        [string]$token
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
    $User = $username
    if ($pass) {
        # Set Credential to $Password parameter input.
        $Credential = $pass
    }
    else {
        $url = "https://$($FunctionApp).azurewebsites.net/api/$($Function)"
        # Retrieve credentials from function app url into a SecureString.
        $a, $b = (Invoke-RestMethod $url -Headers @{ 'x-functions-key' = "$token" }).split(',')
        $Credential = `
            [System.Management.Automation.PSCredential]::new($User, (ConvertTo-SecureString -String $a -Key $b.split('')) )
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
    Clear-Variable -Name "a", "b", "Credential", "token" -Scope Local -ErrorAction SilentlyContinue
}
