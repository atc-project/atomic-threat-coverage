| Title              | DN0007_3_windows_sysmon_network_connection       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | TCP/UDP connections made by a process |
| **Logging Policy** | <ul><li>[LP0005_windows_sysmon_network_connection](../Logging_Policies/LP0005_windows_sysmon_network_connection.md)</li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90003](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90003)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-3.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-3.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>ProcessGuid</li><li>ProcessId</li><li>Image</li><li>User</li><li>Protocol</li><li>Initiated</li><li>SourceIsIpv6</li><li>SourceIp</li><li>SourceHostname</li><li>SourcePort</li><li>SourcePortName</li><li>DestinationIsIpv6</li><li>DestinationIp</li><li>DestinationHostname</li><li>DestinationPort</li><li>DestinationPortName</li></ul> |


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
    <TimeCreated SystemTime="2019-02-05T15:16:29.384924000Z" /> 
    <EventRecordID>16000</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="1828" ThreadID="2764" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>ATC-WIN-7.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="UtcTime">2019-02-05 15:16:17.411</Data> 
    <Data Name="ProcessGuid">{A96EFBF1-A8C9-5C59-0000-0010D274D300}</Data> 
    <Data Name="ProcessId">3900</Data> 
    <Data Name="Image">C:\Users\user1\Desktop\SysinternalsSuite\PsExec.exe</Data> 
    <Data Name="User">ATC-WIN-7\user1</Data> 
    <Data Name="Protocol">tcp</Data> 
    <Data Name="Initiated">true</Data> 
    <Data Name="SourceIsIpv6">false</Data> 
    <Data Name="SourceIp">10.0.0.111</Data> 
    <Data Name="SourceHostname">ATC-WIN-7.atc.local</Data> 
    <Data Name="SourcePort">49603</Data> 
    <Data Name="SourcePortName" /> 
    <Data Name="DestinationIsIpv6">false</Data> 
    <Data Name="DestinationIp">10.0.0.103</Data> 
    <Data Name="DestinationHostname">ATC-WIN-10</Data> 
    <Data Name="DestinationPort">135</Data> 
    <Data Name="DestinationPortName">epmap</Data> 
  </EventData>
</Event>

```




