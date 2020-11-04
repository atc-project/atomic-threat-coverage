| Title              | DN_0100_Passive_DNS_log       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Log from Passive DNS |
| **Logging Policy** | <ul><li>[LP0048_Passive_DNS_logging](../Logging_Policies/LP0048_Passive_DNS_logging.md)</li></ul> |
| **References**     | <ul><li>[None](None)</li></ul> |
| **Platform**       | Linux    |
| **Type**           | queries log        |
| **Channel**        | passivedns     |
| **Provider**       | Passive DNS    |
| **Fields**         | <ul><li>date</li><li>record_type</li><li>client_ip</li><li>src_ip</li><li>destination_ip</li><li>dst_ip</li><li>ttl</li><li>domain_name</li><li>query</li><li>dns_query</li><li>answer</li><li>parent_domain</li><li>question_length</li></ul> |


## Log Samples

### Raw Log

```
1523230478.705932||192.168.1.235||8.8.8.8||IN||facebook.com.||TXT||"v=spf1 redirect=_spf.facebook.com"||21323||1

```




