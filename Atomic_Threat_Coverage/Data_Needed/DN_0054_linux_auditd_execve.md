| Title              | DN_0054_linux_auditd_execve       |
|:-------------------|:------------------|
| **Description**    | Linux auditd log of process (binary) execution (execeve syscall) with command line arguments |
| **Logging Policy** | <ul><li>[LP_0031_linux_auditd_execve](../Logging_Policies/LP_0031_linux_auditd_execve.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/linux-audit/audit-documentation](https://github.com/linux-audit/audit-documentation)</li><li>[https://github.com/linux-audit/audit-documentation/blob/master/specs/fields/field-dictionary.csv](https://github.com/linux-audit/audit-documentation/blob/master/specs/fields/field-dictionary.csv)</li><li>[https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/app-audit_reference](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/app-audit_reference)</li></ul> |
| **Platform**       | Linux    |
| **Type**           | EXECVE        |
| **Channel**        | auditd     |
| **Provider**       | auditd    |
| **Fields**         | <ul><li>type</li><li>msg</li><li>argc</li><li>a0</li><li>a1</li><li>a2</li><li>a3</li></ul> |


## Log Samples

### Raw Log

```
type=EXECVE msg=audit(1564425065.452:651): argc=3 a0="ls" a1="-l" a2="/var/lib/pgsql"
```




