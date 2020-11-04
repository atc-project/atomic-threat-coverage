| Title              | DN_0009_5_windows_sysmon_process_terminated       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Process has been terminated |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90005](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90005)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>Image</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>5</EventID> 
    <Version>3</Version> 
    <Level>4</Level> 
    <Task>5</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-02-05T15:16:38.833314100Z" /> 
    <EventRecordID>57994</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="3172" ThreadID="4192" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="UtcTime">2019-02-05 15:16:38.821</Data> 
    <Data Name="ProcessGuid">{9683FBB1-A8D6-5C59-0000-001009797000}</Data> 
    <Data Name="ProcessId">2440</Data> 
    <Data Name="Image">C:\Windows\PSEXESVC.exe</Data> 
  </EventData>
</Event>

```




