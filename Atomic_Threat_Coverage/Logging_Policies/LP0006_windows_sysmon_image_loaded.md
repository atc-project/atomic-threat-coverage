| Title            | LP0006_windows_sysmon_image_loaded                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | The image loaded event logs when a module is loaded in a specific process.  This event is disabled by default and needs to be configured with the –l option.  It indicates the process in which the module is loaded, hashes and signature information.  The signature is created asynchronously for performance reasons and indicates if the file was removed after loading.  This event should be configured carefully, as monitoring all image load events will generate a large number of events.                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul><li>7</li></ul>         |
| **References**   | <ul><li>[https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)</li></ul> |



## Configuration

Sysmon event id 7 is disabled by default. 
It can be enabled by specyfying -l option
However due to high level of produced logs it should be filtred with configuration file
Sample configuration might be found here: https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml

