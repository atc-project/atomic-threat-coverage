| Title          | DN_0002_windows_process_creation_with_commandline_4688                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | Windows process creation log, including command line.                                                                                                |
| Logging Policy | <ul><li>[LP_0001_windows_audit_process_creation](../Logging_Policies/LP_0001_windows_audit_process_creation.md)</li><li>[LP_0002_windows_audit_process_creation_with_commandline](../Logging_Policies/LP_0002_windows_audit_process_creation_with_commandline.md)</li></ul> |
| References     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4688.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4688.md)</li></ul>                                  |
| Platform       | Windows    																																															  |
| Type           | Windows Log        																																															  |
| Channel        | Security     																																															  |
| Provider       | Microsoft-Windows-Security-Auditing    																																															  |
| Fields         | <ul><li>EventID</li><li>Hostname</li><li>Username</li><li>UserSid</li><li>ProcessPid</li><li>ProcessName</li><li>NewProcessName</li><li>Image</li><li>CommandLine</li><li>ProcessCommandLine</li><li>ProcesssCommandLine</li><li>ParentProcessPid</li><li>ParentImage</li><li>ParentProcessName</li><li>MandatoryLabel</li><li>TokenElevationType</li><li>LogonId</li></ul>                                               |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4688</EventID> 
    <Version>2</Version> 
    <Level>0</Level> 
    <Task>13312</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-11-12T02:24:52.377352500Z" /> 
    <EventRecordID>2814</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="4" ThreadID="400" /> 
    <Channel>Security</Channel> 
    <Computer>WIN-GG82ULGC9GO.contoso.local</Computer> 
    <Security /> 
  </System>
- <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data> 
    <Data Name="SubjectUserName">WIN-GG82ULGC9GO$</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x3e7</Data> 
    <Data Name="NewProcessId">0x2bc</Data> 
    <Data Name="NewProcessName">C:\\Windows\\System32\\rundll32.exe</Data> 
    <Data Name="TokenElevationType">%%1938</Data> 
    <Data Name="ProcessId">0xe74</Data> 
    <Data Name="TargetUserSid">S-1-5-21-1377283216-344919071-3415362939-1104</Data> 
    <Data Name="TargetUserName">dadmin</Data> 
    <Data Name="TargetDomainName">CONTOSO</Data> 
    <Data Name="TargetLogonId">0x4a5af0</Data> 
    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data> 
    <Data Name="MandatoryLabel">S-1-16-8192</Data> 
  </EventData>
</Event>
```




