| Title          | LP_0011_windows_sysmon_DnsQuery                                                                     |
|:---------------|:--------------------------------------------------------------------------------|
| Description    | Enables logging of events related to DNS queries and responses                                                               |
| Default        | Not configured                                                                   |
| Event Volume   | High                                                                    |
| EventID        | <ul><li>22</li></ul>         |
| References     | <ul><li>[https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-22-dnsevent-dns-query](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-22-dnsevent-dns-query)</li></ul> |



## Configuration

This configuration should be further tunned according to baseline (filtration required).

Sample configuration:
```
<DnsQuery onmatch="exclude">
</DnsQuery>
```


