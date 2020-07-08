| Title              | DN0058_4656_handle_to_an_object_was_requested       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event indicates that specific access was requested for an object.  The object could be a file system, kernel, or registry object, or a file  system object on removable storage or a device. If access was declined,  a Failure event is generated. This event generates only if the object’s  SACL has the required ACE to handle the use of specific access rights |
| **Logging Policy** | <ul><li>[LP0104_windows_audit_removable_storage](../Logging_Policies/LP0104_windows_audit_removable_storage.md)</li><li>[LP0039_windows_audit_kernel_object](../Logging_Policies/LP0039_windows_audit_kernel_object.md)</li><li>[LP0102_windows_audit_file_system](../Logging_Policies/LP0102_windows_audit_file_system.md)</li><li>[LP0103_windows_audit_registry](../Logging_Policies/LP0103_windows_audit_registry.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4656.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4656.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>ObjectServer</li><li>ObjectType</li><li>ObjectName</li><li>HandleId</li><li>TransactionId</li><li>AccessList</li><li>AccessReason</li><li>AccessMask</li><li>PrivilegeList</li><li>RestrictedSidCount</li><li>ProcessId</li><li>ProcessName</li><li>ResourceAttributes</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4656</EventID> 
    <Version>1</Version> 
    <Level>0</Level> 
    <Task>12800</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8010000000000000</Keywords> 
    <TimeCreated SystemTime="2015-09-18T22:15:19.346776600Z" /> 
    <EventRecordID>274057</EventRecordID> 
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
    <Data Name="HandleId">0x0</Data> 
    <Data Name="TransactionId">{00000000-0000-0000-0000-000000000000}</Data> 
    <Data Name="AccessList">%%1538 %%1541 %%4416 %%4417 %%4418 %%4419 %%4420 %%4423 %%4424</Data> 
    <Data Name="AccessReason">%%1538: %%1804 %%1541: %%1809 %%4416: %%1809 %%4417: %%1809 %%4418: %%1802 D:(D;;LC;;;S-1-5-21-3457937927-2839227994-823803824-1104) %%4419: %%1809 %%4420: %%1809 %%4423: %%1811 D:(A;OICI;FA;;;S-1-5-21-3457937927-2839227994-823803824-1104) %%4424: %%1809</Data> 
    <Data Name="AccessMask">0x12019f</Data> 
    <Data Name="PrivilegeList">-</Data> 
    <Data Name="RestrictedSidCount">0</Data> 
    <Data Name="ProcessId">0x1074</Data> 
    <Data Name="ProcessName">C:\\Windows\\System32\\notepad.exe</Data> 
    <Data Name="ResourceAttributes">S:AI(RA;ID;;;;WD;("Impact\_MS",TI,0x10020,3000))</Data> 
  </EventData>
</Event>

```




