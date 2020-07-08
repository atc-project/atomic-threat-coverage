| Title            | LP0031_linux_auditd_execve                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Policy to enable auditd to log process (binary) execution (execeve syscall)  with command line arguments                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul></ul>         |
| **References**   | <ul><li>[https://github.com/linux-audit/audit-documentation](https://github.com/linux-audit/audit-documentation)</li><li>[https://github.com/Neo23x0/auditd](https://github.com/Neo23x0/auditd)</li></ul> |



## Configuration

Command to log the execve system call:

```
auditctl -a exit,always -S execve
```

Command to enable logging of specific executable invocation:

```
auditctl -a exit,always -S execve -F path=/usr/bin/rrdtool
```

To permanently implement auditd rules, edit `/etc/audit/rules.d/audit.rules` file:

```
-a exit,always -S execve                           # log everything
```

Command to enable rules (execute as root):

```
augenrules --load
```


