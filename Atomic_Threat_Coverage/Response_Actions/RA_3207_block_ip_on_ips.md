| Title                       |  Block IP on IPS         |
|:---------------------------:|:--------------------|
| **ID**                      | RA3207            |
| **Description**             | Block an IP address in an IPS   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Stage**                   | containment         |
| **Linked Analytics** |<ul><li>MS_IPS</li></ul>|

### Workflow

Block an IP address on an IPS using its native filtering functionality.  
Warning:  

- If not all corporate hosts access the internet through the IPS, you will **not** be able to contain the threat using this Response Action.  
- Be careful blocking IP addresses. Make sure it's not a cloud provider or a hoster. If you would like to block something that is hosted on a well-known cloud provider or on a big hoster IP address, you should block a specific URL using alternative Response Action.  
