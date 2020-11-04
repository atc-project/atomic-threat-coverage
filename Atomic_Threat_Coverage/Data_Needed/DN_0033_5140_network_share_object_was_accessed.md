| Title              | DN_0033_5140_network_share_object_was_accessed       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Network share object (file or folder) was accessed |
| **Logging Policy** | <ul><li>[LP_0030_windows_audit_file_share](../Logging_Policies/LP_0030_windows_audit_file_share.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-5140.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-5140.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>ObjectType</li><li>IpAddress</li><li>IpPort</li><li>ShareName</li><li>ShareLocalPath</li><li>AccessMask</li><li>AccessList</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>5140</EventID> 
    <Version>1</Version> 
    <Level>0</Level> 
    <Task>12808</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-09-18T02:45:13.581231400Z" /> 
    <EventRecordID>268495</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="4" ThreadID="772" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="SubjectUserName">dadmin</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x541f35</Data> 
    <Data Name="ObjectType">File</Data> 
    <Data Name="IpAddress">10.0.0.100</Data> 
    <Data Name="IpPort">49212</Data> 
    <Data Name="ShareName">\\\\\*\\Documents</Data> 
    <Data Name="ShareLocalPath">\\??\\C:\\Documents</Data> 
    <Data Name="AccessMask">0x1</Data> 
    <Data Name="AccessList">%%4416</Data> 
  </EventData>
</Event>

```




