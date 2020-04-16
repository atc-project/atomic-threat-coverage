| Title                       |  Block IP on IPS         |
|:---------------------------:|:--------------------|
| **ID**                      | RA3207            |
| **Description**             | Block an IP address in an IPS   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Stage**                   | containment         |
| **Linked Analytics** |<ul><li>MS_IPS</li></ul>|

### Workflow

Block ip on IPS using native filtering functionality.
Warning: 
- If not all corporate hosts access internet through the IPS, this Response Action cannot guarantee containment of threat.
- Be careful blocking IP address. Make sure it's not cloud provider or hoster. In this case you have to use blocking by URL something more specific.