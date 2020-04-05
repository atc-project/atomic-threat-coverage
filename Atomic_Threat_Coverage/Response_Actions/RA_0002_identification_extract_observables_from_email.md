| Title                       | RA_0002_identification_extract_observables_from_email         |
|:----------------------------|:--------------------|
| **Description**             | Extract all observables from the original phishing email   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Stage**                   | identification         |
| **Automation**              |<ul><li>thehive</li></ul> |
| **References**              |<ul><li>[https://ubuntuincident.wordpress.com/2010/09/27/extract-email-attachments/](https://ubuntuincident.wordpress.com/2010/09/27/extract-email-attachments/)</li><li>[https://blog.thehive-project.org/2018/07/31/emlparser-a-new-cortex-analyzer-for-eml-files/](https://blog.thehive-project.org/2018/07/31/emlparser-a-new-cortex-analyzer-for-eml-files/)</li></ul> |
| **Linked Response Actions** | None |
| **Linked Analytics**        | None |


### Workflow

Extract the data for further response steps:

- attachments (using munpack tool: `munpack email.eml`)
- from, to, cc
- subject of the email
- received servers path
- list of URLs from the text content of the mail body and attachments

This Response Action could be automated with [TheHive EmlParser](https://blog.thehive-project.org/2018/07/31/emlparser-a-new-cortex-analyzer-for-eml-files/).
