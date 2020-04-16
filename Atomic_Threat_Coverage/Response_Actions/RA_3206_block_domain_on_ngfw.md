| Title                       |  Block domain on NGFW         |
|:---------------------------:|:--------------------|
| **ID**                      | RA3206            |
| **Description**             | Block a domain name on an NGFW   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Stage**                   | containment         |
| **Linked Analytics** |<ul><li>MS_NGFW</li></ul>|

### Workflow

Block domain on NGFW using native filtering functionality.
Warning: 
- If not all corporate hosts access internet through the NGFW, this Response Action cannot guarantee containment of threat.
- Be careful blocking domain names. Make sure it's not cloud provider or hoster. In this case you have to use blocking by URL something more specific.
