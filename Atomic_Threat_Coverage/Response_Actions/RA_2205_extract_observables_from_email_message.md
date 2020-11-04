| Title                       | Extract observables from email message         |
|:---------------------------:|:--------------------|
| **ID**                      | RA2205            |
| **Description**             | Extract observables from an email message   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Category**                | Email      |
| **Stage**                   |[RS0002: Identification](../Response_Stages/RS0002.md)| 
| **Automation** |<ul><li>thehive</li></ul>|
| **References** |<ul><li>[https://ubuntuincident.wordpress.com/2010/09/27/extract-email-attachments/](https://ubuntuincident.wordpress.com/2010/09/27/extract-email-attachments/)</li><li>[https://blog.thehive-project.org/2018/07/31/emlparser-a-new-cortex-analyzer-for-eml-files/](https://blog.thehive-project.org/2018/07/31/emlparser-a-new-cortex-analyzer-for-eml-files/)</li></ul>|

### Workflow

Extract the data for further response steps:  

- attachments (using munpack tool: `munpack email.eml`)  
- from, to, cc  
- subject of the email  
- received servers path  
- list of URLs from the text content of the mail body and attachments  

This Response Action could be automated with [TheHive EmlParser](https://blog.thehive-project.org/2018/07/31/emlparser-a-new-cortex-analyzer-for-eml-files/).  
