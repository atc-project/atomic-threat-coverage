| Title              | DN0024_21_windows_sysmon_WmiEvent       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | When a consumer binds to a filter, this event logs the consumer name and  filter path |
| **Logging Policy** | <ul><li>[LP0010_windows_sysmon_WmiEvent](../Logging_Policies/LP0010_windows_sysmon_WmiEvent.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-21.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-21.md)</li><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90021](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90021)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>EventType</li><li>Operation</li><li>User</li><li>Consumer</li><li>RuleName</li><li>Filter</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>21</EventID> 
    <Version>3</Version> 
    <Level>4</Level> 
    <Task>21</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-02-05T14:44:47.091658300Z" /> 
    <EventRecordID>46714</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="3172" ThreadID="444" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="EventType">WmiBindingEvent</Data> 
    <Data Name="UtcTime">2019-02-05 14:44:47.087</Data> 
    <Data Name="Operation">Created</Data> 
    <Data Name="User">atc-win-10\user1</Data> 
    <Data Name="Consumer">"\\\\.\\ROOT\\subscription:CommandLineEventConsumer.Name=\"AtomicRedTeam-WMIPersistence-Example\""</Data> 
    <Data Name="Filter">"\\\\.\\ROOT\\subscription:__EventFilter.Name=\"AtomicRedTeam-WMIPersistence-Example\""</Data> 
  </EventData>
</Event>

```




