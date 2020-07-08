| Title              | DN0067_4719_system_audit_policy_was_changed       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event generates when the computer's audit policy changes. This event is always logged regardless of the "Audit Policy Change"  sub-category setting |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4719.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4719.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>CategoryId</li><li>SubcategoryId</li><li>SubcategoryGuid</li><li>AuditPolicyChanges</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4719</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>13568</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-09-30T19:57:09.668217100Z" /> 
    <EventRecordID>1049418</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="516" ThreadID="4668" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data> 
    <Data Name="SubjectUserName">DC01$</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x3e7</Data> 
    <Data Name="CategoryId">%%8274</Data> 
    <Data Name="SubcategoryId">%%12807</Data> 
    <Data Name="SubcategoryGuid">{0CCE9223-69AE-11D9-BED3-505054503030}</Data> 
    <Data Name="AuditPolicyChanges">%%8448, %%8450</Data> 
  </EventData>
</Event>

```




