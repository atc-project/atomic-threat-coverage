| Title                       | Access external HTTP logs         |
|:---------------------------:|:--------------------|
| **ID**                      | RA1104            |
| **Description**             | Make sure you have access to external communication HTTP logs   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 2020/05/06 |
| **Category**                | Network      |
| **Stage**                   |[RS0001: Preparation](../Response_Stages/RS0001.md)| 
| **References** |<ul><li>[https://docs.zeek.org/en/current/examples/httpmonitor/](https://docs.zeek.org/en/current/examples/httpmonitor/)</li><li>[https://en.wikipedia.org/wiki/Common_Log_Format](https://en.wikipedia.org/wiki/Common_Log_Format)</li></ul>|
| **Requirements** |<ul><li>MS_border_proxy</li><li>MS_border_ngfw</li><li>DN_zeek_http_log</li></ul>|

### Workflow

Make sure that there is a collection of HTTP connections logs for external communication (from corporate assets to the Internet) configured.  
