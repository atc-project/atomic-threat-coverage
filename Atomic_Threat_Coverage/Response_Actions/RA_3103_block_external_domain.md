| Title                       | Block external domain         |
|:---------------------------:|:--------------------|
| **ID**                      | RA3103            |
| **Description**             | Block an external domain name from being accessed by corporate assets   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Category**                | Network      |
| **Stage**                   |[RS0003: Containment](../Response_Stages/RS0003.md)| 
| **References** |<ul><li>[https://en.wikipedia.org/wiki/DNS_sinkhole](https://en.wikipedia.org/wiki/DNS_sinkhole)</li></ul>|
| **Requirements** |<ul><li>MS_border_proxy</li><li>MS_border_ips</li><li>MS_border_ngfw</li><li>MS_dns_server</li></ul>|

### Workflow

Block an external domain name from being accessed by corporate assets, using the most efficient way.  

Warning:  

- Be careful blocking doman names. Make sure it's not a cloud provider or a hoster. If you would like to block something that is hosted on a well-known cloud provider or on a big hoster doman, you should block (if applicable) a specific URL using alternative Response Action   
