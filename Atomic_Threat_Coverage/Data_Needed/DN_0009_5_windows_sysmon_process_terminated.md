| Title          | DN_0009_5_windows_sysmon_process_terminated                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | Process has been terminated                                                                                                |
| Logging Policy | <ul><li>[None](../Logging_Policies/None.md)</li></ul> |
| References     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90005](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90005)</li></ul>                                  |
| Platform       | Windows    																																															  |
| Type           | Windows Log        																																															  |
| Channel        | Microsoft-Windows-Sysmon/Operational     																																															  |
| Provider       | Microsoft-Windows-Sysmon    																																															  |
| Fields         | <ul><li>EventID</li><li>Computer</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>Image</li></ul>                                               |


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
      <TimeCreated SystemTime="2017-04-28T22:13:20.896253900Z" />
      <EventRecordID>11235</EventRecordID>
      <Correlation />
      <Execution ProcessID="3216" ThreadID="3964" />
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>rfsH.lab.local</Computer>
      <Security UserID="S-1-5-18" />
  </System>
- <EventData>
      <Data Name="UtcTime">2017-04-28 22:13:20.895</Data>
      <Data Name="ProcessGuid">{A23EAE89-BD28-5903-0000-001009665D00}</Data>
      <Data Name="ProcessId">12684</Data>
      <Data Name="Image">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data>
  </EventData>
  </Event>

```




