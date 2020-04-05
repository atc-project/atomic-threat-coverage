| Title              | DN_0019_15_windows_sysmon_FileCreateStreamHash       |
|:-------------------|:------------------|
| **Description**    | This event logs when a named file stream is created, and it generates events  that log the hash of the contents of the file to which the stream is assigned  (the unnamed stream), as well as the contents of the named stream |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-15.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-15.md)</li><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>Image</li><li>TargetFilename</li><li>CreationUtcTime</li><li>Hash</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>15</EventID> 
    <Version>2</Version> 
    <Level>4</Level> 
    <Task>15</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-01-21T12:43:53.385072700Z" /> 
    <EventRecordID>34115</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="2052" ThreadID="4092" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="UtcTime">2019-01-21 12:43:53.368</Data> 
    <Data Name="ProcessGuid">{9683FBB1-A860-5C45-0000-0010274F1400}</Data> 
    <Data Name="ProcessId">6604</Data> 
    <Data Name="Image">C:\windows\Explorer.EXE</Data> 
    <Data Name="TargetFilename">C:\Users\user1\Downloads\wce_v1_42beta_x64\wce.exe</Data> 
    <Data Name="CreationUtcTime">2013-11-11 22:41:40.000</Data> 
    <Data Name="Hash">MD5=CCF1D1573F175299ADE01C07791A6541,SHA256=68A15A34C2E28B9B521A240B948634617D72AD619E3950BC6DC769E60A0C3CF2</Data> 
  </EventData>
</Event>

```




