| Title            | LP0047_BIND_DNS_queries                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Configuration to enable DNS queries log on BIND server                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul><li>None</li></ul>         |
| **References**   | <ul><li>[None](None)</li></ul> |



## Configuration

logging {
        channel queries_log {
                file "/var/named/log/queries" versions 600 size 40m;
                print-category yes;
                print-severity yes;
                print-time yes;
                severity info;
        };
        category queries { queries_log; };


