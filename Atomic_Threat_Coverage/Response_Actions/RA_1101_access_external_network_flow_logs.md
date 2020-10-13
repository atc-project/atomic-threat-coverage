| Title                       | Access external network flow logs         |
|:---------------------------:|:--------------------|
| **ID**                      | RA1101            |
| **Description**             | Make sure you have access to external communication Network Flow logs   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 2020/05/06 |
| **Category**                | Network      |
| **Stage**                   |[RS0001: Preparation](../Response_Stages/RS0001.md)| 
| **References** |<ul><li>[https://en.wikipedia.org/wiki/NetFlow](https://en.wikipedia.org/wiki/NetFlow)</li><li>[https://www.plixer.com/blog/how-accurate-is-sampled-netflow/](https://www.plixer.com/blog/how-accurate-is-sampled-netflow/)</li></ul>|
| **Requirements** |<ul><li>MS_border_firewall</li><li>MS_border_ngfw</li><li>DN_zeek_conn_log</li></ul>|

### Workflow

Make sure that there is a collection of Network Flow logs for external communication (from corporate assets to the Internet) configured.  
If there is no option to configure it on a network device, you can install a special software on each endpoint and collect it from them.  

Warning:  

- There is a feature called ["NetFlow Sampling"](https://www.plixer.com/blog/how-accurate-is-sampled-netflow/), that eliminates the value of the Network Flow logs for some of the tasks, such as "check if some host communicated to an external IP". Make sure it's disabled or you have an alternative way to collect Network Flow logs  
