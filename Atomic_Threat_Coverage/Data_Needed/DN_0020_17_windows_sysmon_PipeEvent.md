| Title          | DN_0020_17_windows_sysmon_PipeEvent                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | This event generates when a named pipe is created. Malware often uses named  pipes for interprocess communication
                                                                                                |
| Logging Policy | <ul><li>[LP_0009_windows_sysmon_PipeEvent](../Logging_Policies/LP_0009_windows_sysmon_PipeEvent.md)</li></ul> |
| References     | <ul><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-17.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-17.md)</li><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90017](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90017)</li></ul>                                  |
| Platform       | Windows   |
| Type           | Applications and Services Logs 		|
| Channel        | Microsoft-Windows-Sysmon/Operational    |
| Provider       | Microsoft-Windows-Sysmon   |
| Fields         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>PipeName</li><li>Image</li></ul>                                               |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>17</EventID> 
    <Version>1</Version> 
    <Level>4</Level> 
    <Task>17</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-02-05T13:37:34.396695400Z" /> 
    <EventRecordID>46617</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="3172" ThreadID="4192" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="UtcTime">2019-02-05 13:37:34.396</Data> 
    <Data Name="ProcessGuid">{9683FBB1-919E-5C59-0000-0010A0E53B00}</Data> 
    <Data Name="ProcessId">7128</Data> 
    <Data Name="PipeName">\PSEXESVC-ATC-WIN-7-2728-stdin</Data> 
    <Data Name="Image">C:\windows\PSEXESVC.exe</Data> 
  </EventData>
</Event>

```




