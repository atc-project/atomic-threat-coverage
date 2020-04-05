| Title              | DN_0023_20_windows_sysmon_WmiEvent       |
|:-------------------|:------------------|
| **Description**    | This event logs the registration of WMI consumers, recording the consumer  name, log, and destination |
| **Logging Policy** | <ul><li>[LP_0010_windows_sysmon_WmiEvent](../Logging_Policies/LP_0010_windows_sysmon_WmiEvent.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-20.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-20.md)</li><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90020](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90020)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>EventType</li><li>Operation</li><li>User</li><li>Name</li><li>Type</li><li>Destination</li><li>RuleName</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>20</EventID> 
    <Version>3</Version> 
    <Level>4</Level> 
    <Task>20</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-02-05T14:44:42.518512400Z" /> 
    <EventRecordID>46713</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="3172" ThreadID="444" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="EventType">WmiConsumerEvent</Data> 
    <Data Name="UtcTime">2019-02-05 14:44:42.510</Data> 
    <Data Name="Operation">Created</Data> 
    <Data Name="User">atc-win-10\user1</Data> 
    <Data Name="Name">"AtomicRedTeam-WMIPersistence-Example"</Data> 
    <Data Name="Type">Command Line</Data> 
    <Data Name="Destination">"C:\\windows\\System32\\notepad.exe"</Data> 
  </EventData>
</Event>

```




