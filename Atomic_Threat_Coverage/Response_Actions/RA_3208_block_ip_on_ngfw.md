| Title                       |  Block IP on NGFW         |
|:---------------------------:|:--------------------|
| **ID**                      | RA3208            |
| **Description**             | Block an IP address on an NGFW   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Stage**                   | containment         |
| **Linked Analytics** |<ul><li>MS_NGFW</li></ul>|

### Workflow

Block an IP address with NGFW using native filtering functionality.
Warning: 
- If not all corporate hosts access internet through the NGFW, this Response Action cannot guarantee containment of threat.
- Be careful blocking IP address. Make sure it's not cloud provider or hoster. In this case you have to use blocking by URL something more specific.
