| Title          | DN_0007_3_windows_sysmon_network_connection                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | TCP/UDP connections made by a process                                                                                                |
| Logging Policy | <ul><li>[LP_0005_windows_sysmon_network_connection](../Logging_Policies/LP_0005_windows_sysmon_network_connection.md)</li></ul> |
| References     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90003](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90003)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-3.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-3.md)</li></ul>                                  |
| Platform       | Windows    																																															  |
| Type           | Windows Log        																																															  |
| Channel        | Microsoft-Windows-Sysmon/Operational     																																															  |
| Provider       | Microsoft-Windows-Sysmon    																																															  |
| Fields         | <ul><li>EventID</li><li>Computer</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>Image</li><li>User</li><li>Protocol</li><li>Initiated</li><li>SourceIsIpv6</li><li>SourceIp</li><li>SourceHostname</li><li>SourcePort</li><li>SourcePortName</li><li>DestinationIsIpv6</li><li>DestinationIp</li><li>DestinationHostname</li><li>DestinationPort</li><li>DestinationPortName</li></ul>                                               |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>3</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>3</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2017-04-28T22:12:23.657698300Z" />
    <EventRecordID>10953</EventRecordID>
    <Correlation />
    <Execution ProcessID="3216" ThreadID="3976" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>rfsH.lab.local</Computer>
    <Security UserID="S-1-5-18" />
  </System>
- <EventData>
    <Data Name="UtcTime">2017-04-28 22:12:22.557</Data>
    <Data Name="ProcessGuid">{A23EAE89-BD28-5903-0000-00102F345D00}</Data>
    <Data Name="ProcessId">13220</Data>
    <Data Name="Image">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data>
    <Data Name="User">LAB\rsmith</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="Initiated">true</Data>
    <Data Name="SourceIsIpv6">false</Data>
    <Data Name="SourceIp">192.168.1.250</Data>
    <Data Name="SourceHostname">rfsH.lab.local</Data>
    <Data Name="SourcePort">3328</Data>
    <Data Name="SourcePortName">
    </Data>
    <Data Name="DestinationIsIpv6">false</Data>
    <Data Name="DestinationIp">104.130.229.150</Data>
    <Data Name="DestinationHostname">
    </Data>
    <Data Name="DestinationPort">443</Data>
    <Data Name="DestinationPortName">https</Data>
  </EventData>
  </Event>

```




