| Title              | DN_0002_4688_windows_process_creation_with_commandline       |
|:-------------------|:------------------|
| **Description**    | Windows process creation log, including command line |
| **Logging Policy** | <ul><li>[LP_0001_windows_audit_process_creation](../Logging_Policies/LP_0001_windows_audit_process_creation.md)</li><li>[LP_0002_windows_audit_process_creation_with_commandline](../Logging_Policies/LP_0002_windows_audit_process_creation_with_commandline.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4688.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/95b9d7c01805839c067e352d1d16702604b15f11/windows/security/threat-protection/auditing/event-4688.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Hostname</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>NewProcessId</li><li>ProcessId</li><li>NewProcessName</li><li>ProcessName</li><li>NewProcessName</li><li>Image</li><li>TokenElevationType</li><li>CommandLine</li><li>ProcessCommandLine</li><li>ProcesssCommandLine</li><li>TargetUserSid</li><li>TargetUserName</li><li>TargetDomainName</li><li>TargetLogonId</li><li>ParentProcessName</li><li>ParentImage</li><li>MandatoryLabel</li></ul> |


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
    <TimeCreated SystemTime="2019-02-06T20:34:57.910980700Z" /> 
    <EventRecordID>3542561</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="4" ThreadID="92" /> 
    <Channel>Security</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-540864798-2899685673-3651185163-500</Data> 
    <Data Name="SubjectUserName">user1</Data> 
    <Data Name="SubjectDomainName">atc-win-10</Data> 
    <Data Name="SubjectLogonId">0xcdd96</Data> 
    <Data Name="NewProcessId">0x12d0</Data> 
    <Data Name="NewProcessName">C:\Users\user1\Desktop\PSTools\PsExec64.exe</Data> 
    <Data Name="TokenElevationType">%%1936</Data> 
    <Data Name="ProcessId">0x21d4</Data> 
    <Data Name="CommandLine">PsExec64.exe -i -s -d cmd</Data> 
    <Data Name="TargetUserSid">S-1-0-0</Data> 
    <Data Name="TargetUserName">-</Data> 
    <Data Name="TargetDomainName">-</Data> 
    <Data Name="TargetLogonId">0x0</Data> 
    <Data Name="ParentProcessName">C:\Windows\System32\cmd.exe</Data> 
    <Data Name="MandatoryLabel">S-1-16-12288</Data> 
  </EventData>
</Event>

```




