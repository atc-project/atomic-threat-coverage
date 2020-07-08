| Title              | DN0056_linux_auditd_syscall       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Linux auditd log of specific system call (syscall) |
| **Logging Policy** | <ul><li>[LP0033_linux_auditd_syscall](../Logging_Policies/LP0033_linux_auditd_syscall.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/linux-audit/audit-documentation](https://github.com/linux-audit/audit-documentation)</li><li>[https://github.com/linux-audit/audit-documentation/blob/master/specs/fields/field-dictionary.csv](https://github.com/linux-audit/audit-documentation/blob/master/specs/fields/field-dictionary.csv)</li><li>[https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/app-audit_reference](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/app-audit_reference)</li><li>[https://access.redhat.com/solutions/36278](https://access.redhat.com/solutions/36278)</li><li>[https://filippo.io/linux-syscall-table/](https://filippo.io/linux-syscall-table/)</li></ul> |
| **Platform**       | Linux    |
| **Type**           | SYSCALL        |
| **Channel**        | auditd     |
| **Provider**       | auditd    |
| **Fields**         | <ul><li>type</li><li>msg</li><li>arch</li><li>syscall</li><li>success</li><li>exit</li><li>a0</li><li>a1</li><li>a2</li><li>a3</li><li>items</li><li>ppid</li><li>pid</li><li>auid</li><li>uid</li><li>gid</li><li>euid</li><li>suid</li><li>fsuid</li><li>egid</li><li>sgid</li><li>fsgid</li><li>tty</li><li>ses</li><li>comm</li><li>exe</li><li>subj</li><li>key</li></ul> |


## Log Samples

### Raw Log

```
type=SYSCALL msg=audit(1529507591.700:304): arch=c000003e syscall=62 success=yes exit=0 a0=829 a1=9 a2=0 a3=829 items=0 ppid=1783 pid=1784 auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="bash" exe="/usr/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="kill_rule"

```




