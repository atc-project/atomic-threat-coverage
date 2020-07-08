| Title              | DN0083_16_access_history_in_hive_was_cleared       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | The access history in hive was cleared updating X keys and creating Y modified pages |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[http://www.eventid.net/display-eventid-16-source-Microsoft-Windows-Kernel-General-eventno-11563-phase-1.htm](http://www.eventid.net/display-eventid-16-source-Microsoft-Windows-Kernel-General-eventno-11563-phase-1.htm)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | System     |
| **Provider**       | Microsoft-Windows-Kernel-General    |
| **Fields**         | <ul><li>EventID</li><li>Hostname</li><li>Computer</li><li>HiveNameLength</li><li>HiveName</li><li>KeysUpdated</li><li>DirtyPages</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
      <Provider Name="Microsoft-Windows-Kernel-General" Guid="{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}" />
      <EventID>16</EventID>
      <Version>0</Version>
      <Level>4</Level>
      <Task>0</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2018-01-12T03:18:59.347973200Z" />
      <EventRecordID>1705</EventRecordID>
      <Correlation />
      <Execution ProcessID="4" ThreadID="540" />
      <Channel>System</Channel>
      <Computer>atc-win-10.atc.local</Computer>
      <Security UserID="S-1-5-18" />
    </System>
  - <EventData>
      <Data Name="HiveNameLength">31</Data>
      <Data Name="HiveName">\SystemRoot\System32\Config\SAM</Data>
      <Data Name="KeysUpdated">65</Data>
      <Data Name="DirtyPages">7</Data>
    </EventData>
  </Event>

```




