| Title            | LP_0010_windows_sysmon_WmiEvent                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Enables logging of events related to usage of windows management interface. Possible events are:
  - WmiEventFilter activity detected
  - WmiEventConsumer activity detected
  - WmiEventConsumerToFilter activity detected                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | Low                                                                    |
| **EventID**      | <ul><li>19</li><li>20</li><li>21</li></ul>         |
| **References**   | <ul><li>[https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)</li></ul> |



## Configuration

This configuration should be further tunned according to baseline

Sample configuration:
```
  <WmiEvent onmatch="exclude">
  </WmiEvent>
```

