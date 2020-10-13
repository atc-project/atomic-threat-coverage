| Title              | DN_0092_unix_generic_syslog       |
|:-------------------|:------------------|
| **Description**    | Unix generic syslog |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://github.com/Neo23x0/sigma/blob/master/rules/linux/lnx_buffer_overflows.yml](https://github.com/Neo23x0/sigma/blob/master/rules/linux/lnx_buffer_overflows.yml)</li></ul> |
| **Platform**       | Unix    |
| **Type**           | generic        |
| **Channel**        | syslog     |
| **Provider**       | syslog    |
| **Fields**         | <ul><li>timestamp</li><li>uid</li><li>message</li></ul> |


## Log Samples

### Raw Log

```
Nov 12 18:47:02 foo.bar.baz unix: rpc.ttdbserverd[1932] attempt to execute code on stack by uid 0

```




