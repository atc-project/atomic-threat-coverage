| Title                       | RA_0036_containment_block_domain_on_ngfw         |
|:----------------------------|:--------------------|
| **Description**             | Block a domain name with NGFW   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Stage**                   | containment         |
| **Automation**              | None |
| **References**              | None |
| **Linked Response Actions** | None |
| **Linked Analytics**        |<ul><li>MS_NGFW</li></ul> |


### Workflow

Block domain on NGFW using native filtering functionality.
Warning: 
- If not all corporate hosts access internet through the NGFW, this Response Action cannot guarantee containment of threat.
- Be careful blocking domain names. Make sure it's not cloud provider or hoster. In this case you have to use blocking by URL something more specific.
