# ActiveUsersAudit Module
## Get-ActiveUsersAudit
### Synopsis
Active Directory Audit with Keyvault retrieval option.
### Syntax
```powershell

Get-ActiveUsersAudit [[-AttachementFolderPath] <String>] [[-Enabled] <Boolean>] [[-DaysInactive] <Int32>] [[-SendMailMessage]] [-Clean] [<CommonParameters>]

Get-ActiveUsersAudit [[-AttachementFolderPath] <String>] [[-Enabled] <Boolean>] [[-DaysInactive] <Int32>] [-SendMailMessage] [-Password] <SecureString> [-UserName] <String> [[-SMTPServer] <String>] [[-Port] <Int32>] [-To] <String> [[-From] <String>] [-Clean] [<CommonParameters>]

Get-ActiveUsersAudit [[-AttachementFolderPath] <String>] [[-Enabled] <Boolean>] [[-DaysInactive] <Int32>] [-SendMailMessage] [-FunctionApp] <String> [-Function] <String> [-ApiToken] <String> [-UserName] <String> [[-SMTPServer] <String>] [[-Port] <Int32>] [-To] <String> [[-From] <String>] [-Clean] [<CommonParameters>]





```
### Parameters
| Name  | Alias  | Description | Required? | Pipeline Input | Default Value |
| - | - | - | - | - | - |
| <nobr>AttachementFolderPath</nobr> |  | Default path is C:\\temp\\ActiveUserAuditLogs. This is the folder where attachments are going to be saved. | false | true \(ByPropertyName\) | C:\\temp\\ActiveUserAuditLogs |
| <nobr>Enabled</nobr> |  | Choose to search for either enabled or disabled Active Directory Users \(IE: $true or $false\) | false | true \(ByPropertyName\) | True |
| <nobr>DaysInactive</nobr> |  | Defaults to 90 days in the past. Specifies how far back to look for accounts last logon. If logon is within 90 days, it won't be included. | false | true \(ByPropertyName\) | 90 |
| <nobr>SendMailMessage</nobr> |  | Adds parameters for sending Audit Report as an Email. | false | true \(ByPropertyName\) | False |
| <nobr>Password</nobr> |  | Use this parameter to active the parameterset associated with using a clear-text password instead of a function URI. | true | true \(ByPropertyName\) |  |
| <nobr>FunctionApp</nobr> |  | Azure Function App Name. | true | true \(ByPropertyName\) |  |
| <nobr>Function</nobr> |  | Azure Function App's Function Name. Ex. "HttpResponse1" | true | true \(ByPropertyName\) |  |
| <nobr>ApiToken</nobr> |  | Private Function Key | true | true \(ByPropertyName\) |  |
| <nobr>UserName</nobr> |  | Specify the account with an active mailbox and MFA disabled. Ensure the account has delegated access for Send On Behalf for any UPN set in the "$From" Parameter | true | true \(ByPropertyName\) |  |
| <nobr>SMTPServer</nobr> |  | Defaults to Office 365 SMTP relay. Enter optional relay here. | false | true \(ByPropertyName\) | smtp.office365.com |
| <nobr>Port</nobr> |  | SMTP Port to Relay | false | true \(ByPropertyName\) | 587 |
| <nobr>To</nobr> |  | Recipient of the attachment outputs. | true | true \(ByPropertyName\) |  |
| <nobr>From</nobr> |  | Defaults to the same account as $UserName unless the parameter is set. The email will appear as it was sent from the UPN listed here. Ensure the Account stated in the $UserName has delegated access to send on behalf of the account you add to the $From parameter. | false | true \(ByPropertyName\) | $UserName |
| <nobr>Clean</nobr> |  | Remove installed modules during run. | false | true \(ByPropertyName\) | False |
### Note
Can take password as input into secure string instead of URI. Adding the password parameter right after username when calling the function will trigger the correct parameterset.

### Examples
**EXAMPLE 1**
```powershell
Get-ActiveUsersAudit -Verbose
```


**EXAMPLE 2**
```powershell
Get-ActiveUsersAudit -SendMailMessage -FunctionApp "<FunctionAppName>" -Function "<FunctionHttpTriggerName>" -ApiToken "<APIKEY>" -UserName "helpdesk@domain.com" -To "support@domain.com" -Verbose
```


**EXAMPLE 3**
```powershell
Get-ActiveUsersAudit -SendMailMessage -UserName "helpdesk@domain.com" -Password "Password" -To "support@domain.com" -Verbose
```


