| Title            | LP_0033_linux_auditd_syscall                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Policy to enable auditd to log of specific system call (syscall)                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul></ul>         |
| **References**   | <ul><li>[https://github.com/linux-audit/audit-documentation](https://github.com/linux-audit/audit-documentation)</li><li>[https://filippo.io/linux-syscall-table/](https://filippo.io/linux-syscall-table/)</li><li>[https://access.redhat.com/solutions/36278](https://access.redhat.com/solutions/36278)</li><li>[https://github.com/Neo23x0/auditd](https://github.com/Neo23x0/auditd)</li></ul> |



## Configuration

Command to log kill syscall for x64 CPU architecture:

```
auditctl -a exit,always -F arch=b64 -S kill
```

You can configure variety of [syscalls](https://filippo.io/linux-syscall-table/).
If the system is 32 bit OS, you need to set it with "arch=b32".

To permanently implement auditd rules, edit `/etc/audit/rules.d/audit.rules` file:

```
-a exit,always -F arch=b64 -S kill -k kill_signal
```

Command to enable rules (execute as root):

```
augenrules --load
```


