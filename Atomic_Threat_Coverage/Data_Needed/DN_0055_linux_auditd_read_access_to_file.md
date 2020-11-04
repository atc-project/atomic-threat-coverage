| Title              | DN_0055_linux_auditd_read_access_to_file       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Linux auditd log of read access to file |
| **Logging Policy** | <ul><li>[LP_0034_linux_auditd_read_access_to_file](../Logging_Policies/LP_0034_linux_auditd_read_access_to_file.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/linux-audit/audit-documentation](https://github.com/linux-audit/audit-documentation)</li><li>[https://github.com/linux-audit/audit-documentation/blob/master/specs/fields/field-dictionary.csv](https://github.com/linux-audit/audit-documentation/blob/master/specs/fields/field-dictionary.csv)</li><li>[https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/app-audit_reference](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/app-audit_reference)</li></ul> |
| **Platform**       | Linux    |
| **Type**           | PATH        |
| **Channel**        | auditd     |
| **Provider**       | auditd    |
| **Fields**         | <ul><li>type</li><li>msg</li><li>item</li><li>name</li><li>inode</li><li>dev</li><li>mode</li><li>ouid</li><li>ogid</li><li>rdev</li><li>obj</li><li>objtype</li><li>cap_fp</li><li>cap_fi</li><li>cap_fe</li><li>cap_fver</li></ul> |


## Log Samples

### Raw Log

```
type=PATH msg=audit(1564423065.282:742): item=0 name="/etc/passwd" inode=24673227 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:passwd_file_t:s0 objtype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0

```




