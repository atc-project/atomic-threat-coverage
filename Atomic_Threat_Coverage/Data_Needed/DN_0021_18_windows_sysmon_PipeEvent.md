| Title              | DN_0021_18_windows_sysmon_PipeEvent       |
|:-------------------|:------------------|
| **Description**    | This event logs when a named pipe connection is made between a client and a  server |
| **Logging Policy** | <ul><li>[LP_0009_windows_sysmon_PipeEvent](../Logging_Policies/LP_0009_windows_sysmon_PipeEvent.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-18.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-18.md)</li><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90018](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90018)</li></ul> |
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
    <EventID>18</EventID> 
    <Version>1</Version> 
    <Level>4</Level> 
    <Task>18</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-07-09T04:22:41.815238100Z" /> 
    <EventRecordID>15894</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="1540" ThreadID="3456" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="EventType">ConnectPipe</Data> 
    <Data Name="UtcTime">2019-07-09 04:22:41.814</Data> 
    <Data Name="ProcessGuid">{717CFEC0-1691-5D24-0000-0010663D4100}</Data> 
    <Data Name="ProcessId">6376</Data> 
    <Data Name="PipeName">\crashpad_5624_JOJRKPKWKSIWYAIJ</Data> 
    <Data Name="Image">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data> 
  </EventData>
</Event>

```




