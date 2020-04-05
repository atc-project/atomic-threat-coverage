| Title              | DN_0039_524_system_catalog_has_been_deleted       |
|:-------------------|:------------------|
| **Description**    | The System Catalog has been deleted |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[http://kb.eventtracker.com/evtpass/evtpages/EventId_524_Microsoft-Windows-Backup_61998.asp](http://kb.eventtracker.com/evtpass/evtpages/EventId_524_Microsoft-Windows-Backup_61998.asp)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Application     |
| **Provider**       | Microsoft-Windows-Backup    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Backup" Guid="{1DB28F2E-8F80-4027-8C5A-A11F7F10F62D}" /> 
    <EventID>524</EventID> 
    <Version>0</Version> 
    <Level>4</Level> 
    <Task>0</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-07-16T22:38:38.762505900Z" /> 
    <EventRecordID>457</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="3476" ThreadID="1732" /> 
    <Channel>Application</Channel> 
    <Computer>atc-win-2k12.atc.lab</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  <EventData /> 
</Event>

```




