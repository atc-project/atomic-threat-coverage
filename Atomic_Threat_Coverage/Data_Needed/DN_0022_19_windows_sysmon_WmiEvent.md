| Title              | DN_0022_19_windows_sysmon_WmiEvent       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | When a WMI event filter is registered, which is a method used by malware to  execute, this event logs the WMI namespace, filter name and filter expression |
| **Logging Policy** | <ul><li>[LP_0010_windows_sysmon_WmiEvent](../Logging_Policies/LP_0010_windows_sysmon_WmiEvent.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-19.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/sysmon/event-19.md)</li><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90019](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90019)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Sysmon/Operational     |
| **Provider**       | Microsoft-Windows-Sysmon    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>UtcTime</li><li>EventType</li><li>Operation</li><li>User</li><li>EventNamespace</li><li>Name</li><li>Query</li><li>RuleName</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" /> 
    <EventID>19</EventID> 
    <Version>3</Version> 
    <Level>4</Level> 
    <Task>19</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-02-05T14:44:42.434534600Z" /> 
    <EventRecordID>46712</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="3172" ThreadID="444" /> 
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="RuleName" /> 
    <Data Name="EventType">WmiFilterEvent</Data> 
    <Data Name="UtcTime">2019-02-05 14:44:42.432</Data> 
    <Data Name="Operation">Created</Data> 
    <Data Name="User">atc-win-10\user1</Data> 
    <Data Name="EventNamespace">"root\\CimV2"</Data> 
    <Data Name="Name">"AtomicRedTeam-WMIPersistence-Example"</Data> 
    <Data Name="Query">"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"</Data> 
  </EventData>
</Event>

```




