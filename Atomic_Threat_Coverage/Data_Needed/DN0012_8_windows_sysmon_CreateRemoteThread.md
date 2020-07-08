| Title              | DN0012_8_windows_sysmon_CreateRemoteThread       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | The CreateRemoteThread event detects when a process creates a thread in  another process |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90008](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90008)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-8.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-8.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>SourceProcessGuid</li><li>SourceProcessId</li><li>SourceImage</li><li>TargetProcessGuid</li><li>TargetProcessId</li><li>TargetImage</li><li>NewThreadId</li><li>StartAddress</li><li>StartModule</li><li>StartFunction</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>8</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>8</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2017-05-13T22:53:43.214864300Z" />
    <EventRecordID>739823</EventRecordID>
    <Correlation />
    <Execution ProcessID="2848" ThreadID="3520" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>atc-win-10.atc.local</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  - <EventData>
    <Data Name="UtcTime">2017-05-13 22:53:43.214</Data>
    <Data Name="SourceProcessGuid">{A23EAE89-8E6D-5917-0000-0010DFAF5004}</Data>
    <Data Name="SourceProcessId">8804</Data>
    <Data Name="SourceImage">C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\Remote Debugger\x64\msvsmon.exe</Data>
    <Data Name="TargetProcessGuid">{A23EAE89-8E5A-5917-0000-00100E3E4D04}</Data>
    <Data Name="TargetProcessId">2024</Data>
    <Data Name="TargetImage">C:\repos\Supercharger\Mtg.Supercharger.ControllerService\bin\x64\Debug\Mtg.Supercharger.ControllerService.exe</Data>
    <Data Name="NewThreadId">20532</Data>
    <Data Name="StartAddress">0x00007FFB09321970</Data>
    <Data Name="StartModule">C:\Windows\SYSTEM32\ntdll.dll</Data>
    <Data Name="StartFunction">DbgUiRemoteBreakin</Data>
  </EventData>
</Event>

```




