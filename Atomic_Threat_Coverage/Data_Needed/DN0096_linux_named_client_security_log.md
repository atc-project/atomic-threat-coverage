| Title              | DN0096_linux_named_client_security_log       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Linux named (BIND) messages relating to client access and security |
| **Logging Policy** | <ul><li>[LP0034_linux_named_client_security_log](../Logging_Policies/LP0034_linux_named_client_security_log.md)</li></ul> |
| **References**     | <ul><li>[https://kb.isc.org/docs/aa-01526](https://kb.isc.org/docs/aa-01526)</li><li>[http://jhurani.com/linux/2013/02/12/named-disable-xfer.html](http://jhurani.com/linux/2013/02/12/named-disable-xfer.html)</li></ul> |
| **Platform**       | Linux    |
| **Type**           | client_security_log        |
| **Channel**        | client_security_log     |
| **Provider**       | named    |
| **Fields**         | <ul><li>Hostname</li><li>ClientIP</li><li>ClientPort</li><li>ZoneTransferDomain</li><li>Message</li></ul> |


## Log Samples

### Raw Log

```
28-Aug-2019 02:03:13.739 security: error: client 192.168.0.2#53274 (atc.local): zone transfer 'atc.local/AXFR/IN' denied

```




