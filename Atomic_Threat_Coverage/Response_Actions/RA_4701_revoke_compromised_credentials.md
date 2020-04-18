| Title                       |  Revoke compromised credentials         |
|:---------------------------:|:--------------------|
| **ID**                      | RA4701            |
| **Description**             | Response Action for compromised credentials revocation   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Stage**                   | eradication         |
| **References** |<ul><li>[https://adsecurity.org/?p=556](https://adsecurity.org/?p=556)</li><li>[https://adsecurity.org/?p=483](https://adsecurity.org/?p=483)</li></ul>|

### Workflow

On this step, you supposed to know what kind of credentials have been compromised.  
You need to revoke them in your Identity and Access Management system where they were created (i.e. Windows AD) using native functionality.  

Warning:  

- If the adversary has generated Golden Ticket in Windows Domain/forest, you have to revoke KRBTGT Account password **twice** for each domain in a forest and proceed to monitor malicious activity for next 20 minutes (Domain Controller KDC service doesn’t perform validate the user account until the TGT is older than 20 minutes old)
