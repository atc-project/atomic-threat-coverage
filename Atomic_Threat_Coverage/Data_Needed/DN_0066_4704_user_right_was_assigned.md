| Title              | DN_0066_4704_user_right_was_assigned       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event generates every time local user right policy is changed and  user right was assigned to an account. You will see unique event for  every user |
| **Logging Policy** | <ul><li>[LP0105_windows_audit_authorization_policy_change](../Logging_Policies/LP0105_windows_audit_authorization_policy_change.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4704.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4704.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>TargetSid</li><li>PrivilegeList</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4704</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>13570</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-10-02T22:08:07.136050600Z" /> 
    <EventRecordID>1049866</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="500" ThreadID="1216" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data> 
    <Data Name="SubjectUserName">DC01$</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x3e7</Data> 
    <Data Name="TargetSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="PrivilegeList">SeAuditPrivilege SeIncreaseWorkingSetPrivilege</Data> 
  </EventData>
</Event>

```




