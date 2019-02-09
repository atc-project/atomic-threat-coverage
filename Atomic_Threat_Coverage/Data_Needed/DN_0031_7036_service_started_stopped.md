| Title          | DN_0031_7036_service_started_stopped                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | Service entered the running/stopped state                                                                                                |
| Logging Policy | <ul><li>[N](../Logging_Policies/N.md)</li><li>[o](../Logging_Policies/o.md)</li><li>[n](../Logging_Policies/n.md)</li><li>[e](../Logging_Policies/e.md)</li></ul> |
| References     | <ul><li>[h](h)</li><li>[t](t)</li><li>[t](t)</li><li>[p](p)</li><li>[:](:)</li><li>[/](/)</li><li>[/](/)</li><li>[w](w)</li><li>[w](w)</li><li>[w](w)</li><li>[.](.)</li><li>[e](e)</li><li>[v](v)</li><li>[e](e)</li><li>[n](n)</li><li>[t](t)</li><li>[i](i)</li><li>[d](d)</li><li>[.](.)</li><li>[n](n)</li><li>[e](e)</li><li>[t](t)</li><li>[/](/)</li><li>[d](d)</li><li>[i](i)</li><li>[s](s)</li><li>[p](p)</li><li>[l](l)</li><li>[a](a)</li><li>[y](y)</li><li>[-](-)</li><li>[e](e)</li><li>[v](v)</li><li>[e](e)</li><li>[n](n)</li><li>[t](t)</li><li>[i](i)</li><li>[d](d)</li><li>[-](-)</li><li>[7](7)</li><li>[0](0)</li><li>[3](3)</li><li>[6](6)</li><li>[-](-)</li><li>[s](s)</li><li>[o](o)</li><li>[u](u)</li><li>[r](r)</li><li>[c](c)</li><li>[e](e)</li><li>[-](-)</li><li>[S](S)</li><li>[e](e)</li><li>[r](r)</li><li>[v](v)</li><li>[i](i)</li><li>[c](c)</li><li>[e](e)</li><li>[%](%)</li><li>[2](2)</li><li>[0](0)</li><li>[C](C)</li><li>[o](o)</li><li>[n](n)</li><li>[t](t)</li><li>[r](r)</li><li>[o](o)</li><li>[l](l)</li><li>[%](%)</li><li>[2](2)</li><li>[0](0)</li><li>[M](M)</li><li>[a](a)</li><li>[n](n)</li><li>[a](a)</li><li>[g](g)</li><li>[e](e)</li><li>[r](r)</li><li>[-](-)</li><li>[e](e)</li><li>[v](v)</li><li>[e](e)</li><li>[n](n)</li><li>[t](t)</li><li>[n](n)</li><li>[o](o)</li><li>[-](-)</li><li>[1](1)</li><li>[5](5)</li><li>[2](2)</li><li>[9](9)</li><li>[-](-)</li><li>[p](p)</li><li>[h](h)</li><li>[a](a)</li><li>[s](s)</li><li>[e](e)</li><li>[-](-)</li><li>[1](1)</li><li>[.](.)</li><li>[h](h)</li><li>[t](t)</li><li>[m](m)</li></ul>                                  |
| Platform       | Windows   |
| Type           | Windows Log 		|
| Channel        | System    |
| Provider       | Service Control Manager   |
| Fields         | <ul><li>EventID</li><li>ProcessID</li><li>ThreadID</li><li>Computer</li><li>param1</li><li>param2</li></ul>                                               |


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




