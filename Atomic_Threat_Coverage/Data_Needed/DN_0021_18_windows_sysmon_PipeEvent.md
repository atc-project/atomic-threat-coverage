| Title          | DN_0021_18_windows_sysmon_PipeEvent                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | This event logs when a named pipe connection is made between a client and a server.                                                                                                |
| Logging Policy | <ul><li>[LP_0009_windows_sysmon_PipeEvent](../Logging_Policies/LP_0009_windows_sysmon_PipeEvent.md)</li></ul> |
| References     | <ul><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-18.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-18.md)</li><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90018](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90018)</li></ul>                                  |
| Platform       | Windows    																																															  |
| Type           | Windows Log        																																															  |
| Channel        | Microsoft-Windows-Sysmon/Operational     																																															  |
| Provider       | Microsoft-Windows-Sysmon    																																															  |
| Fields         | <ul><li>EventID</li><li>Computer</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>PipeName</li><li>Image</li></ul>                                               |


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
      <TimeCreated SystemTime="2019-02-05T13:37:34.457379300Z" /> 
      <EventRecordID>46620</EventRecordID> 
      <Correlation /> 
      <Execution ProcessID="3172" ThreadID="4192" /> 
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
      <Computer>tdl-win-10.tdl.local</Computer> 
      <Security UserID="S-1-5-18" /> 
    </System>
  - <EventData>
      <Data Name="RuleName" /> 
      <Data Name="UtcTime">2019-02-05 13:37:34.455</Data> 
      <Data Name="ProcessGuid">{9683FBB1-8B5F-5C59-0000-0010EB030000}</Data> 
      <Data Name="ProcessId">4</Data> 
      <Data Name="PipeName">\PSEXESVC-TDL-WIN-7-2728-stdin</Data> 
      <Data Name="Image">System</Data> 
    </EventData>
  </Event>

```




