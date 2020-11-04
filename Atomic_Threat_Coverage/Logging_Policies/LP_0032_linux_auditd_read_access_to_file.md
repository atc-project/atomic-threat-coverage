| Title            | LP_0032_linux_auditd_read_access_to_file                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Policy to enable auditd to log read access to file                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | Medium                                                                    |
| **EventID**      | <ul></ul>         |
| **References**   | <ul><li>[https://github.com/linux-audit/audit-documentation](https://github.com/linux-audit/audit-documentation)</li><li>[https://github.com/Neo23x0/auditd](https://github.com/Neo23x0/auditd)</li></ul> |



## Configuration

Command to log read access to `/etc/passwd`:

```
auditctl -w /etc/passwd -p r
```

To permanently implement auditd rules, edit `/etc/audit/rules.d/audit.rules` file:

```
-w /etc/passwd -p r
```

Command to enable rules (execute as root):

```
augenrules --load
```


