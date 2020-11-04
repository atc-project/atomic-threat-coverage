| Title              | DN_0086_4720_user_account_was_created       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | A user account was created |
| **Logging Policy** | <ul><li>[LP_0026_windows_audit_user_account_management](../Logging_Policies/LP_0026_windows_audit_user_account_management.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4720.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4720.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li><li>TargetUserName</li><li>TargetDomainName</li><li>TargetSid</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>PrivilegeList</li><li>SamAccountName</li><li>DisplayName</li><li>UserPrincipalName</li><li>HomeDirectory</li><li>HomePath</li><li>ScriptPath</li><li>ProfilePath</li><li>UserWorkstations</li><li>PasswordLastSet</li><li>AccountExpires</li><li>PrimaryGroupId</li><li>AllowedToDelegateTo</li><li>OldUacValue</li><li>NewUacValue</li><li>UserAccountControl</li><li>UserParameters</li><li>SidHistory</li><li>LogonHours</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4720</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>13824</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2019-07-11T23:09:42.994762700Z" /> 
    <EventRecordID>1346</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="532" ThreadID="564" /> 
    <Channel>Security</Channel> 
    <Computer>atc-win-2k12</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="TargetUserName">newuser</Data> 
    <Data Name="TargetDomainName">ATC-WIN-2K12</Data> 
    <Data Name="TargetSid">S-1-5-21-1566719857-3102892733-3273982148-1005</Data> 
    <Data Name="SubjectUserSid">S-1-5-21-1566719857-3102892733-3273982148-1001</Data> 
    <Data Name="SubjectUserName">yugoslavskiy</Data> 
    <Data Name="SubjectDomainName">ATC-WIN-2K12</Data> 
    <Data Name="SubjectLogonId">0x14c6b</Data> 
    <Data Name="PrivilegeList">-</Data> 
    <Data Name="SamAccountName">newuser</Data> 
    <Data Name="DisplayName">%%1793</Data> 
    <Data Name="UserPrincipalName">-</Data> 
    <Data Name="HomeDirectory">%%1793</Data> 
    <Data Name="HomePath">%%1793</Data> 
    <Data Name="ScriptPath">%%1793</Data> 
    <Data Name="ProfilePath">%%1793</Data> 
    <Data Name="UserWorkstations">%%1793</Data> 
    <Data Name="PasswordLastSet">%%1794</Data> 
    <Data Name="AccountExpires">%%1794</Data> 
    <Data Name="PrimaryGroupId">513</Data> 
    <Data Name="AllowedToDelegateTo">-</Data> 
    <Data Name="OldUacValue">0x0</Data> 
    <Data Name="NewUacValue">0x15</Data> 
    <Data Name="UserAccountControl">%%2080 %%2082 %%2084</Data> 
    <Data Name="UserParameters">%%1793</Data> 
    <Data Name="SidHistory">-</Data> 
    <Data Name="LogonHours">%%1797</Data> 
  </EventData>
</Event>
```




