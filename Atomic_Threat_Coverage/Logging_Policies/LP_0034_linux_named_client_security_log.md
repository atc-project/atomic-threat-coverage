| Title            | LP_0034_linux_named_client_security_log                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Description**  | Policy to enable BIND (named) DNS server client_security log                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | Low                                                                    |
| **EventID**      | <ul></ul>         |
| **References**   | <ul><li>[https://kb.isc.org/docs/aa-01526](https://kb.isc.org/docs/aa-01526)</li></ul> |



## Configuration

Edit `/etc/bind/named.conf` file, adding the next configuration:

```
logging {
      channel client_security_log {
              file "/var/named/log/client_security" versions 3 size 20m;
              print-time yes;
              print-category yes;
              print-severity yes;
              severity info;
      };
      category security { client_security_log; };
      category client{ client_security_log; };
```

Restart service to implementation configuration:

```
systemctl restart bind9.service
```


