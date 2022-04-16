[![CI](https://github.com/CriticalSolutionsNetwork/Get-ActiveUserAudit/actions/workflows/blank.yml/badge.svg?branch=main&event=workflow_dispatch)](https://github.com/CriticalSolutionsNetwork/Get-ActiveUserAudit/actions/workflows/blank.yml)

# ActiveUsersAudit Module
## Get-ActiveUsersAudit
### Synopsis
Active Directory Audit with Keyvault retrieval option.
### Syntax
```powershell

Get-ActiveUsersAudit [-UserName] <String> [[-Uri] <String>] [-To] <String> [[-From] <String>] [-AttachementFolderPath] <String> [-DaysInactive] <String> 
[<CommonParameters>]

Get-ActiveUsersAudit [-UserName] <String> [[-Password] <SecureString>] [-To] <String> [[-From] <String>] [-AttachementFolderPath] <String> [-DaysInactive] <String> 
[<CommonParameters>]





```
### Parameters
| Name  | Alias  | Description | Required? | Pipeline Input | Default Value |
| - | - | - | - | - | - |
| <nobr>UserName</nobr> |  | Specify the account with an active mailbox and MFA disabled. Ensure the account has delegated access for Send On Behalf for any UPN set in the "$From" Parameter | true | true \(ByValue, ByPropertyName\) |  |
| <nobr>Uri</nobr> |  | Function App URL for specific customer or department needing access to the key. | false | true \(ByPropertyName\) |  |
| <nobr>Password</nobr> |  | Use this parameter to active the parameterset associated with using a clear-text password instead of a function URI. | false | true \(ByPropertyName\) |  |
| <nobr>To</nobr> |  | Recipient of the attachment outputs. | true | true \(ByPropertyName\) |  |
| <nobr>From</nobr> |  | Defaults to the same account as $UserName unless the parameter is set. The email will appear as it was sent from the UPN listed here. Ensure the Account stated in the $UserName has delegated access to send on behalf of the account you add to the $From parameter. | false | true \(ByPropertyName\) | $UserName |
| <nobr>AttachementFolderPath</nobr> |  | Default path is C:\\temp\\ActiveUserAuditLogs. This is the folder where attachments are going to be saved. | true | true \(ByPropertyName\) | C:\\temp\\ActiveUserAuditLogs |
| <nobr>DaysInactive</nobr> |  | Defaults to 90 days in the past. Specifies how far back to look for accounts last logon. If logon is within 90 days, it won't be included. | true | true \(ByPropertyName\) | 90 |
### Inputs
 - Inputs \(if any\)

### Outputs
 - Output \(if any\)

### Note
Can take password as input into secure string instead of URI. Adding the password parameter right after username when calling the function will trigger the correct parameterset.

### Examples
**EXAMPLE 1**
```powershell
Get-ActiveUsersAudit -UserName "helpdesk@domain.com" -Uri "https://<instance>.azurewebsites.net/api/HttpTrigger1?code=<Personal URL CODE>&clientId=<FunctionHTMLName>" -To "support@domain.com" -From "helpdesk@domain.com" -AttachementFolderPath "C:\temp" -DaysInactive 90 -Verbose
```


**EXAMPLE 2**
```powershell
Get-ActiveUsersAudit -UserName "helpdesk@domain.com" -Password "<Clear-Text String>" -To "support@domain.com" -From "helpdesk@domain.com" -AttachementFolderPath "C:\temp" -DaysInactive 90 -Verbose
```



