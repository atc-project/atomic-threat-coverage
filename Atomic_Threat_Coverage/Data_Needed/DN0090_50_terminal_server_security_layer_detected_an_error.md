| Title              | DN0090_50_terminal_server_security_layer_detected_an_error       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | The RDP protocol component <component> detected an error in the  protocol stream and has disconnected the client |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[http://www.eventid.net/display-eventid-50-source-TermDD-eventno-606-phase-1.htm](http://www.eventid.net/display-eventid-50-source-TermDD-eventno-606-phase-1.htm)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | System     |
| **Provider**       | TermDD    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="TermDD" /> 
    <EventID Qualifiers="49162">50</EventID> 
    <Level>2</Level> 
    <Task>0</Task> 
    <Keywords>0x80000000000000</Keywords> 
    <TimeCreated SystemTime="2019-07-12T02:37:29.871133100Z" /> 
    <EventRecordID>5483</EventRecordID> 
    <Channel>System</Channel> 
    <Computer>atc-win-7</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data>\Device\Termdd</Data> 
    <Data>X.224</Data> 
    <Binary>00000B00020034000000000032000AC00000000032000AC0000000000000000000000000000000000B00000016030100C30100</Binary> 
  </EventData>
</Event>
```




