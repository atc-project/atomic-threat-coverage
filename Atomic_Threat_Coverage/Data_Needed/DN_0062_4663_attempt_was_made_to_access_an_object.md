| Title              | DN_0062_4663_attempt_was_made_to_access_an_object       |
|:-------------------|:------------------|
| **Description**    | This event indicates that a specific operation was performed on an object.  The object could be a file system, kernel, or registry object, or a file  system object on removable storage or a device. This event generates only  if object’s SACL has required ACE to handle specific access right use.  The main difference with "4656: A handle to an object was requested."  event is that 4663 shows that access right was used instead of just  requested and 4663 doesn’t have Failure events |
| **Logging Policy** | <ul><li>[LP_0102_windows_audit_file_system](../Logging_Policies/LP_0102_windows_audit_file_system.md)</li><li>[LP_0039_windows_audit_kernel_object](../Logging_Policies/LP_0039_windows_audit_kernel_object.md)</li><li>[LP_0103_windows_audit_registry](../Logging_Policies/LP_0103_windows_audit_registry.md)</li><li>[LP_0104_windows_audit_removable_storage](../Logging_Policies/LP_0104_windows_audit_removable_storage.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4663.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4663.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>ObjectServer</li><li>ObjectType</li><li>ObjectName</li><li>HandleId</li><li>AccessList</li><li>AccessMask</li><li>ProcessId</li><li>ProcessName</li><li>ResourceAttributes</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4663</EventID> 
    <Version>1</Version> 
    <Level>0</Level> 
    <Task>12800</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-09-18T22:13:54.770429700Z" /> 
    <EventRecordID>273866</EventRecordID> 
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
    <Data Name="SubjectLogonId">0x4367b</Data> 
    <Data Name="ObjectServer">Security</Data> 
    <Data Name="ObjectType">File</Data> 
    <Data Name="ObjectName">C:\\Documents\\HBI Data.txt</Data> 
    <Data Name="HandleId">0x1bc</Data> 
    <Data Name="AccessList">%%4417 %%4418</Data> 
    <Data Name="AccessMask">0x6</Data> 
    <Data Name="ProcessId">0x458</Data> 
    <Data Name="ProcessName">C:\\Windows\\System32\\notepad.exe</Data> 
    <Data Name="ResourceAttributes">S:AI(RA;ID;;;;WD;("Impact\_MS",TI,0x10020,3000))</Data> 
  </EventData>
</Event>

```




