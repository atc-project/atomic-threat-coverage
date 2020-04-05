| Title              | DN_0094_linux_sshd_log       |
|:-------------------|:------------------|
| **Description**    | OpenSSH SSH daemon (sshd) log |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://en.wikibooks.org/wiki/OpenSSH/Logging_and_Troubleshooting](https://en.wikibooks.org/wiki/OpenSSH/Logging_and_Troubleshooting)</li></ul> |
| **Platform**       | Linux    |
| **Type**           | auth        |
| **Channel**        | auth.log     |
| **Provider**       | sshd    |
| **Fields**         | <ul><li>Hostname</li><li>UserName</li><li>Daemon</li><li>Program</li><li>Message</li></ul> |


## Log Samples

### Raw Log

```
May 18 16:41:20 hostname sshd[890]: error: buffer_get_string_ret: buffer_get failed

```




