| Title              | DN_0038_400_engine_state_is_changed_from_none_to_available       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Information about PowerShell engine state. Engine state is changed from None to Available |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/powershell/events/event-400.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/powershell/events/event-400.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Windows PowerShell     |
| **Provider**       | PowerShell    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
      <Provider Name="PowerShell" /> 
      <EventID Qualifiers="0">400</EventID> 
      <Level>4</Level> 
      <Task>4</Task> 
      <Keywords>0x80000000000000</Keywords> 
      <TimeCreated SystemTime="2019-02-05T15:13:04.885878700Z" /> 
      <EventRecordID>50575</EventRecordID> 
      <Channel>Windows PowerShell</Channel> 
      <Computer>atc-win-10.atc.local</Computer> 
      <Security /> 
    </System>
  - <EventData>
      <Data>Available</Data> 
      <Data>None</Data> 
      <Data>NewEngineState=Available PreviousEngineState=None SequenceNumber=13 HostName=Windows PowerShell ISE Host HostVersion=5.1.17134.407 HostId=9478b487-c2ea-4aa8-8eb3-9b7bad25b39f HostApplication=C:\windows\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe EngineVersion=5.1.17134.407 RunspaceId=9f89fa00-ca26-402e-9dea-29c6d2447f7b PipelineId= CommandName= CommandType= ScriptName= CommandPath= CommandLine=</Data> 
    </EventData>
  </Event>
```




