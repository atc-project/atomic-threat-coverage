| Title              | DN_0020_17_windows_sysmon_PipeEvent       |
|:-------------------|:------------------|
| **Description**    | This event generates when a named pipe is created. Malware often uses named  pipes for interprocess communication |
| **Logging Policy** | <ul><li>[LP_0009_windows_sysmon_PipeEvent](../Logging_Policies/LP_0009_windows_sysmon_PipeEvent.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-17.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-17.md)</li><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90017](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90017)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>EventType</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>PipeName</li><li>Image</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>17</EventID> 
    <Version>1</Version> 
    <Level>4</Level> 
    <Task>17</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-07-09T04:21:40.086214400Z" /> 
    <EventRecordID>14921</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="1540" ThreadID="3456" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="EventType">CreatePipe</Data> 
    <Data Name="UtcTime">2019-07-09 04:21:39.850</Data> 
    <Data Name="ProcessGuid">{717CFEC0-1651-5D24-0000-00109AFB3E00}</Data> 
    <Data Name="ProcessId">5624</Data> 
    <Data Name="PipeName">\mojo.5624.7020.12775972776436680360</Data> 
    <Data Name="Image">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data> 
  </EventData>
</Event>

```




