| Title          | DN_0011_7_windows_sysmon_image_loaded                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | The image loaded event logs when a module is loaded in a specific process                                                                                                |
| Logging Policy | <ul><li>[LP_0006_windows_sysmon_image_loaded](../Logging_Policies/LP_0006_windows_sysmon_image_loaded.md)</li></ul> |
| References     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90007](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90007)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-7.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-7.md)</li></ul>                                  |
| Platform       | Windows   |
| Type           | Applications and Services Logs 		|
| Channel        | Microsoft-Windows-Sysmon/Operational    |
| Provider       | Microsoft-Windows-Sysmon   |
| Fields         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>Image</li><li>ImageLoaded</li><li>Hashes</li><li>Signed</li><li>Signature</li><li>SignatureStatus</li></ul>                                               |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>7</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <Task>7</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2017-04-28T22:45:16.663226600Z" />
    <EventRecordID>16636</EventRecordID>
    <Correlation />
    <Execution ProcessID="3216" ThreadID="3964" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>atc-win-10.atc.local</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  - <EventData>
    <Data Name="UtcTime">2017-04-28 22:45:16.662</Data>
    <Data Name="ProcessGuid">{A23EAE89-C5FA-5903-0000-0010BF439000}</Data>
    <Data Name="ProcessId">12536</Data>
    <Data Name="Image">C:\Windows\System32\notepad.exe</Data>
    <Data Name="ImageLoaded">C:\Windows\System32\ole32.dll</Data>
    <Data Name="Hashes">SHA1=B2A2BBCFB69B1F0982C4B82055DAD9BAE4384E4B</Data>
    <Data Name="Signed">true</Data>
    <Data Name="Signature">Microsoft Windows</Data>
    <Data Name="SignatureStatus">Valid</Data>
  </EventData>
</Event>

```




