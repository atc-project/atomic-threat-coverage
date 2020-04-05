| Title              | DN_0061_4660_object_was_deleted       |
|:-------------------|:------------------|
| **Description**    | This event generates when an object was deleted. The object could be a  file system, kernel, or registry object. This event generates only if  "Delete" auditing is set in object’s SACL. This event doesn’t contain  the name of the deleted object (only the Handle ID). It is better to  use "4663(S): An attempt was made to access an object" with DELETE  access to track object deletion. The advantage of this event is that  it’s generated only during real delete operations. In contrast,  "4663(S): An attempt was made to access an object" also generates  during other actions, such as object renaming |
| **Logging Policy** | <ul><li>[LP_0102_windows_audit_file_system](../Logging_Policies/LP_0102_windows_audit_file_system.md)</li><li>[LP_0039_windows_audit_kernel_object](../Logging_Policies/LP_0039_windows_audit_kernel_object.md)</li><li>[LP_0103_windows_audit_registry](../Logging_Policies/LP_0103_windows_audit_registry.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4660.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4660.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>ObjectServer</li><li>HandleId</li><li>ProcessId</li><li>ProcessName</li><li>TransactionId</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4660</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>12800</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-09-18T21:05:28.677152100Z" /> 
    <EventRecordID>270188</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="4" ThreadID="3060" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="SubjectUserName">dadmin</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x4367b</Data> 
    <Data Name="ObjectServer">Security</Data> 
    <Data Name="HandleId">0x1678</Data> 
    <Data Name="ProcessId">0xef0</Data> 
    <Data Name="ProcessName">C:\\Windows\\explorer.exe</Data> 
    <Data Name="TransactionId">{00000000-0000-0000-0000-000000000000}</Data> 
  </EventData>
</Event>

```




