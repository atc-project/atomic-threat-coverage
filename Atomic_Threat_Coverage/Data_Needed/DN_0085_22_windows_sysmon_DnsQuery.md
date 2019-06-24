| Title          | DN_0085_22_windows_sysmon_DnsQuery                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | This event generates when a process executes a DNS query, whether the result is  successful or fails, cached or not                                                                                                |
| Logging Policy | <ul><li>[LP_0011_windows_sysmon_DnsQuery](../Logging_Policies/LP_0011_windows_sysmon_DnsQuery.md)</li></ul> |
| References     | <ul><li>[https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-22-dnsevent-dns-query](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-22-dnsevent-dns-query)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-22.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-22.md)</li></ul>                                  |
| Platform       | Windows   |
| Type           | Applications and Services Logs 		| 
| Channel        | Microsoft-Windows-Sysmon/Operational    |
| Provider       | Microsoft-Windows-Sysmon   |
| Fields         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>RuleName</li><li>ProcessGuid</li><li>ProcessId</li><li>QueryName</li><li>QueryStatus</li><li>QueryResults</li><li>Image</li></ul>                                               |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>22</EventID> 
    <Version>5</Version> 
    <Level>4</Level> 
    <Task>22</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-06-24T00:56:52.053368800Z" /> 
    <EventRecordID>2637</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="5956" ThreadID="4672" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="UtcTime">2019-06-24 00:56:50.125</Data> 
    <Data Name="ProcessGuid">{717CFEC0-1A16-5D10-0000-0010CDEA1F00}</Data> 
    <Data Name="ProcessId">3192</Data> 
    <Data Name="QueryName">kibana.atomicthreatcoverage.com</Data> 
    <Data Name="QueryStatus">0</Data> 
    <Data Name="QueryResults">::ffff:157.230.126.111;</Data> 
    <Data Name="Image">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</Data> 
  </EventData>
</Event>

```




