| Title                       |  Block IP on NGFW         |
|:---------------------------:|:--------------------|
| **ID**                      | RA3208            |
| **Description**             | Block an IP address on a NGFW   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Stage**                   | containment         |
| **Linked Analytics** |<ul><li>MS_NGFW</li></ul>|

### Workflow

Block an IP address on a NGFW using its native filtering functionality.  

Warning:  

- Be careful blocking IP address. Make sure it's not a cloud provider or a hoster. If you would like to block something that is hosted on a well-known cloud provider or on a big hoster IP address, you should (if applicable) block a specific URL using alternative Response Action  
