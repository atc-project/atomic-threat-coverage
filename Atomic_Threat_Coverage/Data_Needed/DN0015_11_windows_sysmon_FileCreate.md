| Title              | DN0015_11_windows_sysmon_FileCreate       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | File create operations are logged when a file is created or overwritten. This  event is useful for monitoring autostart locations, like the Startup folder,  as well as temporary and download directories, which are common places  malware drops during initial infection |
| **Logging Policy** | <ul><li>[LP0008_windows_sysmon_FileCreate](../Logging_Policies/LP0008_windows_sysmon_FileCreate.md)</li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-11.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-11.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>Image</li><li>TargetFilename</li><li>CreationUtcTime</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>11</EventID> 
    <Version>2</Version> 
    <Level>4</Level> 
    <Task>11</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-01-30T15:08:51.296611700Z" /> 
    <EventRecordID>42528</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="3892" ThreadID="5724" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="UtcTime">2019-01-30 15:08:51.287</Data> 
    <Data Name="ProcessGuid">{9683FBB1-9A3F-5C51-0000-0010EB030000}</Data> 
    <Data Name="ProcessId">4</Data> 
    <Data Name="Image">System</Data> 
    <Data Name="TargetFilename">C:\Windows\PSEXESVC.exe</Data> 
    <Data Name="CreationUtcTime">2019-01-30 15:08:51.287</Data> 
  </EventData>
</Event>

```




