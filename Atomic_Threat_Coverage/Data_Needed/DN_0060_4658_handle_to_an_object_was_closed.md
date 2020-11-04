| Title              | DN_0060_4658_handle_to_an_object_was_closed       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event generates when the handle to an object is closed. The object  could be a file system, kernel, or registry object, or a file system  object on removable storage or a device. This event generates only if  Success auditing is enabled for Audit Handle Manipulation subcategory. Typically this event is needed if you need to know how long the handle to the object was open. Otherwise, it might not have any security relevance |
| **Logging Policy** | <ul><li>[LP_0102_windows_audit_file_system](../Logging_Policies/LP_0102_windows_audit_file_system.md)</li><li>[LP_0042_windows_audit_handle_manipulation](../Logging_Policies/LP_0042_windows_audit_handle_manipulation.md)</li><li>[LP_0039_windows_audit_kernel_object](../Logging_Policies/LP_0039_windows_audit_kernel_object.md)</li><li>[LP_0103_windows_audit_registry](../Logging_Policies/LP_0103_windows_audit_registry.md)</li><li>[LP_0104_windows_audit_removable_storage](../Logging_Policies/LP_0104_windows_audit_removable_storage.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4658.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4658.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>ObjectServer</li><li>HandleId</li><li>ProcessId</li><li>ProcessName</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4658</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>12800</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-09-22T00:15:42.910428100Z" /> 
    <EventRecordID>276724</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="4" ThreadID="5056" /> 
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
    <Data Name="HandleId">0x18a8</Data> 
    <Data Name="ProcessId">0xef0</Data> 
    <Data Name="ProcessName">C:\\Windows\\explorer.exe</Data> 
  </EventData>
</Event>

```




