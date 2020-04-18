| Title                       |  Block domain on DNS         |
|:---------------------------:|:--------------------|
| **ID**                      | RA3203            |
| **Description**             | Block a domain on a DNS server   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Stage**                   | containment         |
| **References** |<ul><li>[https://en.wikipedia.org/wiki/DNS_sinkhole](https://en.wikipedia.org/wiki/DNS_sinkhole)</li></ul>|
| **Linked Analytics** |<ul><li>MS_dns_server</li></ul>|

### Workflow

Block a domain name on a DNS Server using its native sinkholing functionality.  

Warning:  

- Be careful blocking doman names. Make sure it's not a cloud provider or a hoster. If you would like to block something that is hosted on a well-known cloud provider or on a big hoster doman, you should block (if applicable) a specific URL using alternative Response Action   
