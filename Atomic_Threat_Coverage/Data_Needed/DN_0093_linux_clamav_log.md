| Title              | DN_0093_linux_clamav_log       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Linux ClamAV anti-virus logs |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.clamav.net](https://www.clamav.net)</li><li>[https://docs.pivotal.io/addon-antivirus/1-4/monitoring-logs.html](https://docs.pivotal.io/addon-antivirus/1-4/monitoring-logs.html)</li><li>[https://github.com/ossec/ossec-hids/blob/master/etc/rules/clam_av_rules.xml](https://github.com/ossec/ossec-hids/blob/master/etc/rules/clam_av_rules.xml)</li></ul> |
| **Platform**       | Linux    |
| **Type**           | None        |
| **Channel**        | ClamAV     |
| **Provider**       | ClamAV    |
| **Fields**         | <ul><li>Hostname</li><li>Signature</li><li>FileName</li><li>FilePath</li></ul> |


## Log Samples

### Raw Log

```
/var/vcap/data/test.txt: Eicar-Test-Signature FOUND

```




