| Title              | DN_0013_9_windows_sysmon_RawAccessRead       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | The RawAccessRead event detects when a process conducts reading operations  from the drive using the \\.\ denotation |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90009](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90009)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-9.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-9.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>Image</li><li>Device</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>9</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>9</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2018-03-22T20:32:22.333778700Z" />
    <EventRecordID>1944686</EventRecordID>
    <Correlation />
    <Execution ProcessID="19572" ThreadID="21888" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>atc-win-10.atc.local</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  - <EventData>
    <Data Name="UtcTime">2018-03-22 20:32:22.332</Data>
    <Data Name="ProcessGuid">{A23EAE89-C65F-5AB2-0000-0010EB030000}</Data>
    <Data Name="ProcessId">4</Data>
    <Data Name="Image">System</Data>
    <Data Name="Device">\Device\HarddiskVolume2</Data>
  </EventData>
</Event>

```




