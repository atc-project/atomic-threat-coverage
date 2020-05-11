| Title                       | Get ability to block external IP address         |
|:---------------------------:|:--------------------|
| **ID**                      | RA1111            |
| **Description**             | Make sure you have the ability to block an external IP address from being accessed by corporate assets   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 06.05.2020 |
| **Category**                | Network      |
| **Stage**                   |[RS0001: Preparation](../Response_Stages/RS0001.md)| 
| **References** |<ul><li>[https://example.com](https://example.com)</li></ul>|
| **Requirements** |<ul><li>MS_border_firewall</li><li>MS_border_proxy</li><li>MS_border_ips</li><li>MS_border_ngfw</li><li>MS_host_firewall</li></ul>|

### Workflow

Make sure you have the ability to create a policy rule in one of the listed Mitigation Systems that will you to block an external IP address from being accessed by corporate assets.  

Warning:  

- Make sure that using the listed systems (1 or multiple) you can control access to the internet of all assets in the infrastructure. In some cases, you will need a guaranteed way to block an external IP address from being accessed by corporate assets completely. If some of the assets are not under the management of the listed Mitigation Systems, (so they can access the internet bypassing these systems), you will not be able to fully achieve the final objective of the Response Action.  
