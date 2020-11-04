| Title              | DN_0008_4_windows_sysmon_sysmon_service_state_changed       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Sysmon service changed status |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90004](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90004)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-4.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-4.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>State</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>4</EventID> 
    <Version>3</Version> 
    <Level>4</Level> 
    <Task>4</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-02-05T13:11:20.289486200Z" /> 
    <EventRecordID>45818</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="3172" ThreadID="4192" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="UtcTime">2019-02-05 13:11:20.281</Data> 
    <Data Name="State">Started</Data> 
    <Data Name="Version">8.00</Data> 
    <Data Name="SchemaVersion">4.10</Data> 
  </EventData>
</Event>

```




