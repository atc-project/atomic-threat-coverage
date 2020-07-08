| Title              | DN0027_4738_user_account_was_changed       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | User object is changed |
| **Logging Policy** | <ul><li>[LP0026_windows_audit_user_account_management](../Logging_Policies/LP0026_windows_audit_user_account_management.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4738.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4738.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>TargetUserName</li><li>Hostname</li><li>TargetDomainName</li><li>TargetSid</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>PrivilegeList</li><li>SamAccountName</li><li>DisplayName</li><li>UserPrincipalName</li><li>HomeDirectory</li><li>HomePath</li><li>ScriptPath</li><li>ProfilePath</li><li>UserWorkstations</li><li>PasswordLastSet</li><li>AccountExpires</li><li>PrimaryGroupId</li><li>AllowedToDelegateTo</li><li>OldUacValue</li><li>NewUacValue</li><li>UserAccountControl</li><li>UserParameters</li><li>SidHistory</li><li>LogonHours</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4738</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>13824</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-08-20T16:22:02.792454100Z" /> 
    <EventRecordID>175413</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="520" ThreadID="1508" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="TargetUserName">ksmith</Data> 
    <Data Name="TargetDomainName">CONTOSO</Data> 
    <Data Name="TargetSid">S-1-5-21-3457937927-2839227994-823803824-6609</Data> 
    <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="SubjectUserName">dadmin</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x30dc2</Data> 
    <Data Name="PrivilegeList">-</Data> 
    <Data Name="SamAccountName">-</Data> 
    <Data Name="DisplayName">-</Data> 
    <Data Name="UserPrincipalName">-</Data> 
    <Data Name="HomeDirectory">-</Data> 
    <Data Name="HomePath">-</Data> 
    <Data Name="ScriptPath">-</Data> 
    <Data Name="ProfilePath">-</Data> 
    <Data Name="UserWorkstations">-</Data> 
    <Data Name="PasswordLastSet">-</Data> 
    <Data Name="AccountExpires">-</Data> 
    <Data Name="PrimaryGroupId">-</Data> 
    <Data Name="AllowedToDelegateTo">-</Data> 
    <Data Name="OldUacValue">0x15</Data> 
    <Data Name="NewUacValue">0x211</Data> 
    <Data Name="UserAccountControl">%%2050 %%2089</Data> 
    <Data Name="UserParameters">-</Data> 
    <Data Name="SidHistory">-</Data> 
    <Data Name="LogonHours">-</Data> 
  </EventData>
</Event>

```




