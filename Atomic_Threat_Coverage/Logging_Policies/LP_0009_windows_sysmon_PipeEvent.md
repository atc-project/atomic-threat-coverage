| Title            | LP_0009_windows_sysmon_PipeEvent                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Enables logging of events related to usage or creation of pipes.                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | Low                                                                    |
| **EventID**      | <ul><li>17</li><li>18</li></ul>         |
| **References**   | <ul><li>[https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)</li></ul> |



## Configuration

This configuration should be further tunned according to baseline

Sample configuration:
```
  <PipeEvent onmatch="exclude">
  </PipeEvent>
```

