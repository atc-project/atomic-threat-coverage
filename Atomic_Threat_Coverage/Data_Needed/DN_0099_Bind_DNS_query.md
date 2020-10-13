| Title              | DN_0099_Bind_DNS_query       |
|:-------------------|:------------------|
| **Description**    | DNS Query from BIND Server |
| **Logging Policy** | <ul><li>[LP_0047_BIND_DNS_queries](../Logging_Policies/LP_0047_BIND_DNS_queries.md)</li></ul> |
| **References**     | <ul><li>[None](None)</li></ul> |
| **Platform**       | Linux    |
| **Type**           | queries log        |
| **Channel**        | queries_log     |
| **Provider**       | BIND    |
| **Fields**         | <ul><li>date</li><li>record_type</li><li>client_ip</li><li>src_ip</li><li>domain_name</li><li>query</li><li>dns_query</li><li>destination_ip</li><li>dst_ip</li><li>parent_domain</li><li>question_length</li></ul> |


## Log Samples

### Raw Log

```
25-Oct-2019 01:22:19.421 queries: info: client 192.168.1.200#51364 (yahoo.com): query: yahoo.com IN TXT + (192.168.1.235)

```




