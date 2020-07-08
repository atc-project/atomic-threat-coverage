| Title              | DN0028_4794_directory_services_restore_mode_admin_password_set       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Directory Services Restore Mode (DSRM) administrator password is changed |
| **Logging Policy** | <ul><li>[LP0026_windows_audit_user_account_management](../Logging_Policies/LP0026_windows_audit_user_account_management.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4794.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4794.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>Workstation</li><li>Status</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4794</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>13824</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-08-18T02:49:26.087748900Z" /> 
    <EventRecordID>172348</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="520" ThreadID="2964" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="SubjectUserName">dadmin</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x36f67</Data> 
    <Data Name="Workstation">DC01</Data> 
    <Data Name="Status">0x0</Data> 
  </EventData>
</Event>

```




