| Title          | DN_0003_windows_sysmon_process_creation_1                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | Windows process creation log, including command line.                                                                                                |
| Logging Policy | <ul><li>[LP_0003_windows_sysmon_process_creation](../Logging_Policies/LP_0003_windows_sysmon_process_creation.md)</li></ul> |
| References     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)</li></ul>                                  |
| Platform       | Windows    																																															  |
| Type           | Windows Log        																																															  |
| Channel        | Microsoft-Windows-Sysmon/Operational     																																															  |
| Provider       | Microsoft-Windows-Sysmon    																																															  |
| Fields         | <ul><li>EventID</li><li>Hostname</li><li>Username</li><li>ProcessGuid</li><li>ProcessId</li><li>ProcessName</li><li>CommandLine</li><li>LogonGuid</li><li>LogonId</li><li>TerminalSessionid</li><li>IntegrityLevel</li><li>Imphash</li><li>Sha256hash</li><li>Sha1hash</li><li>Md5hash</li><li>Image</li><li>ParentImage</li><li>ParentProcessGuid</li><li>ParentProcessId</li><li>ParentProcessName</li><li>ParentCommandLine</li></ul>                                               |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2017-04-28T22:08:22.025812200Z" />
    <EventRecordID>9947</EventRecordID>
    <Correlation />
    <Execution ProcessID="3216" ThreadID="3964" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>test.lab.local</Computer>
    <Security UserID="S-1-5-18" />
  </System>
- <EventData>
    <Data Name="UtcTime">2017-04-28 22:08:22.025</Data>
    <Data Name="ProcessGuid">{A23EAE89-BD56-5903-0000-0010E9D95E00}</Data>
    <Data Name="ProcessId">6228</Data>
    <Data Name="Image">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data>
    <Data Name="CommandLine">"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=utility --lang=en-US --no-sandbox --service-request-channel-token=F47498BBA884E523FA93E623C4569B94 --mojo-platform-channel-handle=3432 /prefetch:8</Data>
    <Data Name="CurrentDirectory">C:\Program Files (x86)\Google\Chrome\Application\58.0.3029.81\</Data>
    <Data Name="User">LAB\rsmith</Data>
    <Data Name="LogonGuid">{A23EAE89-B357-5903-0000-002005EB0700}</Data>
    <Data Name="LogonId">0x7eb05</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">Medium</Data>
    <Data Name="Hashes">SHA1=AAE83ECC4ABEE2E7567E2FF76B2B046C65336731,MD5=283BDCD7B83EEE614897619332E5B938,SHA256=17DD017B7E7D1DC835CDF5E57156A0FF508EBBC7F4A48E65D77E026C33FCB58E,IMPHASH=ED5A55DAB5A02F29D6EE7E0015F91A9F</Data>
    <Data Name="ParentProcessGuid">{A23EAE89-BD28-5903-0000-00102F345D00}</Data>
    <Data Name="ParentProcessId">13220</Data>
    <Data Name="ParentImage">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data>
    <Data Name="ParentCommandLine">"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" </Data>
  </EventData>
</Event>

```




