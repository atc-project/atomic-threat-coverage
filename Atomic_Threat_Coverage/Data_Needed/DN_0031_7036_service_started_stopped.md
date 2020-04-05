| Title              | DN_0031_7036_service_started_stopped       |
|:-------------------|:------------------|
| **Description**    | Service entered the running/stopped state |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[http://www.eventid.net/display-eventid-7036-source-Service%20Control%20Manager-eventno-1529-phase-1.htm](http://www.eventid.net/display-eventid-7036-source-Service%20Control%20Manager-eventno-1529-phase-1.htm)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | System     |
| **Provider**       | Service Control Manager    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>param1</li><li>param2</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  - <System>
    <Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' EventSourceName='Service Control Manager'/>
    <EventID Qualifiers='16384'>7036</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>0</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8080000000000000</Keywords>
    <TimeCreated SystemTime='2019-01-12T16:00:11.920020600Z'/>
    <EventRecordID>41452</EventRecordID>
    <Correlation/>
    <Execution ProcessID='692' ThreadID='828'/>
    <Channel>System</Channel>
    <Computer>EC2AMAZ-D6OFVS8</Computer>
    <Security/>
  </System>
 - <EventData>
    <Data Name='param1'>Device Install Service</Data>
    <Data Name='param2'>running</Data>
    <Binary>44006500760069006300650049006E007300740061006C006C002F0034000000</Binary>
  </EventData>
</Event>

```




