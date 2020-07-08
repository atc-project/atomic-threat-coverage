| Title              | DN0032_5145_network_share_object_was_accessed_detailed       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Network share object (file or folder) was accessed. Detailed log with  AccessReason and RelativeTargetName |
| **Logging Policy** | <ul><li>[LP0029_windows_audit_detailed_file_share](../Logging_Policies/LP0029_windows_audit_detailed_file_share.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-5145.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-5145.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>ObjectType</li><li>IpAddress</li><li>IpPort</li><li>ShareName</li><li>ShareLocalPath</li><li>RelativeTargetName</li><li>AccessMask</li><li>AccessList</li><li>AccessReason</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>5145</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>12811</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-09-17T23:54:48.941761700Z" /> 
    <EventRecordID>267092</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="516" ThreadID="524" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="SubjectUserName">dadmin</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x38d34</Data> 
    <Data Name="ObjectType">File</Data> 
    <Data Name="IpAddress">fe80::31ea:6c3c:f40d:1973</Data> 
    <Data Name="IpPort">56926</Data> 
    <Data Name="ShareName">\\\\\*\\Documents</Data> 
    <Data Name="ShareLocalPath">\\??\\C:\\Documents</Data> 
    <Data Name="RelativeTargetName">Bginfo.exe</Data> 
    <Data Name="AccessMask">0x100081</Data> 
    <Data Name="AccessList">%%1541 %%4416 %%4423</Data> 
    <Data Name="AccessReason">%%1541: %%1801 D:(A;;FA;;;WD) %%4416: %%1801 D:(A;;FA;;;WD) %%4423: %%1801 D:(A;;FA;;;WD)</Data> 
  </EventData>
</Event>

```




