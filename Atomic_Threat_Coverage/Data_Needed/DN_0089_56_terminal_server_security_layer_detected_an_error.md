| Title              | DN_0089_56_terminal_server_security_layer_detected_an_error       |
|:-------------------|:------------------|
| **Description**    | The Terminal Server security layer detected an error in the  protocol stream and has disconnected the client |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[http://www.eventid.net/display-eventid-56-source-TermDD-eventno-9421-phase-1.htm](http://www.eventid.net/display-eventid-56-source-TermDD-eventno-9421-phase-1.htm)</li></ul> |
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
    <EventID Qualifiers="49162">56</EventID>
    <Level>2</Level>
    <Task>0</Task>
    <Keywords>0x80000000000000</Keywords>
    <TimeCreated SystemTime="2019-07-11T22:26:42.723Z" />
    <EventRecordID>147091</EventRecordID>
    <Channel>System</Channel>
    <Computer>atc-demo</Computer>
    <Security />
  </System>
  - <EventData>
    <Data>\Device\Termdd</Data>
    <Binary>00050600010000000000000038000AC00000000039000AC00000000000000000000000000000000030030980</Binary>
  </EventData>
</Event>

```




