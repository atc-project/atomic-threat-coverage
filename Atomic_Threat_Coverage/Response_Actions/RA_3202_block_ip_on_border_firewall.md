| Title                       |  Block IP on border Firewall         |
|:---------------------------:|:--------------------|
| **ID**                      | RA3202            |
| **Description**             | Block an IP address on a border firewall   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Stage**                   | containment         |
| **Linked Analytics** |<ul><li>MS_firewall</li></ul>|

### Workflow

Block ip address on border firewall using native filtering functionality.
Warning: 
- If not all corporate hosts access internet through the border firewall, this Response Action cannot guarantee containment of threat.
- Be careful blocking IP address. Make sure it's not cloud provider or hoster. In this case you have to use blocking by URL something more specific.
