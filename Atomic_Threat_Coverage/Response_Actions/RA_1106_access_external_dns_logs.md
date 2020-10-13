| Title                       | Access external DNS logs         |
|:---------------------------:|:--------------------|
| **ID**                      | RA1106            |
| **Description**             | Make sure you have access to external communication DNS logs   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 2020/05/06 |
| **Category**                | Network      |
| **Stage**                   |[RS0001: Preparation](../Response_Stages/RS0001.md)| 
| **References** |<ul><li>[https://github.com/gamelinux/passivedns](https://github.com/gamelinux/passivedns)</li><li>[https://drive.google.com/drive/u/0/folders/0B5BuM3k0_mF3LXpnYVUtU091Vjg](https://drive.google.com/drive/u/0/folders/0B5BuM3k0_mF3LXpnYVUtU091Vjg)</li></ul>|
| **Requirements** |<ul><li>MS_dns_server</li><li>DN_zeek_dns_log</li></ul>|

### Workflow

Make sure that there is a collection of DNS logs for external communication (from corporate assets to the Internet) configured.  
If there is no option to configure it on a network device/DNS Server, you can install a special software on each endpoint and collect it from them.  

Warning:  

- Make sure that there are both DNS query and answer logs collected. It's quite hard to configure such a collection on MS Windows DNS server and ISC BIND. Sometimes it much easier to use 3rd party solutions to fulfill this requirement.  
- Make sure that DNS traffic to the external (public) DNS servers is blocked by the Border Firewall. This way, corporate DNS servers is the only place assets can resolve the domain names.  
