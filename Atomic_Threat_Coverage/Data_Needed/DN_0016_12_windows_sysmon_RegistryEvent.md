| Title              | DN_0016_12_windows_sysmon_RegistryEvent       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Registry key and value create and delete operations map to this event type,  which can be useful for monitoring for changes to Registry autostart  locations, or specific malware registry modifications |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90012](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90012)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-12.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-12.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>EventType</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>Image</li><li>TargetObject</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>12</EventID> 
    <Version>2</Version> 
    <Level>4</Level> 
    <Task>12</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-01-30T17:05:28.027841800Z" /> 
    <EventRecordID>42938</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="3892" ThreadID="5724" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="EventType">DeleteKey</Data> 
    <Data Name="UtcTime">2019-01-30 17:05:28.023</Data> 
    <Data Name="ProcessGuid">{9683FBB1-D812-5C51-0000-0010F3871201}</Data> 
    <Data Name="ProcessId">10396</Data> 
    <Data Name="Image">C:\Windows\regedit.exe</Data> 
    <Data Name="TargetObject">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\New Key #1</Data> 
  </EventData>
</Event>

```




