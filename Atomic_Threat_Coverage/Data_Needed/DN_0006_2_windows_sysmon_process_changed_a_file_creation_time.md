| Title          | DN_0006_process_changed_a_file_creation_time_2                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | Explicit modification of file creation timestamp by a process                                                                                                |
| Logging Policy | <ul><li>[None](../Logging_Policies/None.md)</li></ul> |
| References     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90002](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90002)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-2.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-2.md)</li></ul>                                  |
| Platform       | Windows    																																															  |
| Type           | Windows Log        																																															  |
| Channel        | Microsoft-Windows-Sysmon/Operational     																																															  |
| Provider       | Microsoft-Windows-Sysmon    																																															  |
| Fields         | <ul><li>EventID</li><li>Computer</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>Image</li><li>TargetFilename</li><li>CreationUtcTime</li><li>PreviousCreationUtcTime</li></ul>                                               |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>2</EventID>
    <Version>4</Version>
    <Level>4</Level>
    <Task>2</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2017-07-30T23:26:47.322369100Z" />
    <EventRecordID>5256170</EventRecordID>
    <Correlation />
    <Execution ProcessID="4740" ThreadID="5948" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>rfsH.lab.local</Computer>
    <Security UserID="S-1-5-18" />
</System>
- <EventData>
    <Data Name="UtcTime">2017-07-30 23:26:47.321</Data>
    <Data Name="ProcessGuid">{A23EAE89-EF48-5978-0000-00104832B112}</Data>
    <Data Name="ProcessId">25968</Data>
    <Data Name="Image">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data>
    <Data Name="TargetFilename">C:\Users\rsmith.LAB\AppData\Local\Google\Chrome\User Data\Default\c61f44ce-5bb0-4efe-acc1-246fa8a3df1d.tmp</Data>
    <Data Name="CreationUtcTime">2016-11-25 18:21:47.692</Data>
    <Data Name="PreviousCreationUtcTime">2017-07-30 23:26:47.317</Data>
  </EventData>
</Event>

```




