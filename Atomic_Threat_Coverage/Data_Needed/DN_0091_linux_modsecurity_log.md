| Title              | DN_0091_linux_modsecurity_log       |
|:-------------------|:------------------|
| **Description**    | Mod_security (Web Application Firewall) audit/error log |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.nginx.com/blog/modsecurity-logging-and-debugging/](https://www.nginx.com/blog/modsecurity-logging-and-debugging/)</li><li>[https://www.cryptobells.com/mod_security-json-audit-logs-revisited/](https://www.cryptobells.com/mod_security-json-audit-logs-revisited/)</li></ul> |
| **Platform**       | Linux    |
| **Type**           | modsecurity        |
| **Channel**        | modsecurity     |
| **Provider**       | modsecurity    |
| **Fields**         | <ul><li>timestamp</li><li>hostname</li><li>client</li><li>uri</li></ul> |


## Log Samples

### Raw Log

```
[Thu Jul 02 04:14:31 2018] [error] [client 190.222.135.100] mod_security: Access denied with code 500. Pattern match "SomePattern" at HEADER("USER-AGENT") [hostname "samplesite.com"] [uri "/some/uri"]

```




