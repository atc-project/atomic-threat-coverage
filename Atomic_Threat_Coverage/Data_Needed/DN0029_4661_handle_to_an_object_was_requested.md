| Title              | DN0029_4661_handle_to_an_object_was_requested       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | A handle was requested for either an Active Directory object or a Security  Account Manager (SAM) object |
| **Logging Policy** | <ul><li>[LP0027_windows_audit_directory_service_access](../Logging_Policies/LP0027_windows_audit_directory_service_access.md)</li><li>[LP0028_windows_audit_sam](../Logging_Policies/LP0028_windows_audit_sam.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4794.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4794.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>ObjectServer</li><li>ObjectType</li><li>ObjectName</li><li>HandleId</li><li>TransactionId</li><li>AccessList</li><li>AccessMask</li><li>PrivilegeList</li><li>Properties</li><li>RestrictedSidCount</li><li>ProcessId</li><li>ProcessName</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4661</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>14080</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-09-30T00:11:56.547696700Z" /> 
    <EventRecordID>1048009</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="520" ThreadID="528" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="SubjectUserName">dadmin</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x4280e</Data> 
    <Data Name="ObjectServer">Security Account Manager</Data> 
    <Data Name="ObjectType">SAM\_DOMAIN</Data> 
    <Data Name="ObjectName">DC=contoso,DC=local</Data> 
    <Data Name="HandleId">0xdd64d36870</Data> 
    <Data Name="TransactionId">{00000000-0000-0000-0000-000000000000}</Data> 
    <Data Name="AccessList">%%5400</Data> 
    <Data Name="AccessMask">0x2d</Data> 
    <Data Name="PrivilegeList">Ā</Data> 
    <Data Name="Properties">-</Data> 
    <Data Name="RestrictedSidCount">2949165</Data> 
    <Data Name="ProcessId">0x9000a000d002d</Data> 
    <Data Name="ProcessName">{bf967a90-0de6-11d0-a285-00aa003049e2} %%5400 {ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501}</Data> 
  </EventData>
</Event>

```




