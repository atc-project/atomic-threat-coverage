| Title          | LP_0005_windows_sysmon_network_connection                                                                     |
|:---------------|:--------------------------------------------------------------------------------|
| Description    | The network connection event logs TCP/UDP connections on the machine.  It is disabled by default. Each connection is linked to a process  through the ProcessId and ProcessGUID fields. The event also contains  the source and destination host names IP addresses, port numbers and IPv6 status.                                                               |
| Default        | Not configured                                                                   |
| Event Volume   | High                                                                    |
| EventID        | <ul><li>3</li></ul>         |
| References     | <ul><li>[https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)</li></ul> |



## Configuration

Sysmon event id 3 is disabled by default. 
It can be enabled by specyfying -n option
However due to high level of produced logs it should be filtred with configuration file
Sample configuration might be found here: https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml

