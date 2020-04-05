| Title                       | RA_0001_identification_get_original_email         |
|:----------------------------|:--------------------|
| **Description**             | Obtain the original phishing email   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 31.01.2019 |
| **Stage**                   | identification         |
| **Automation**              | None |
| **References**              |<ul><li>[https://www.lifewire.com/save-an-email-as-an-eml-file-in-gmail-1171956](https://www.lifewire.com/save-an-email-as-an-eml-file-in-gmail-1171956)</li><li>[https://eml.tooutlook.com/](https://eml.tooutlook.com/)</li></ul> |
| **Linked Response Actions** | None |
| **Linked Analytics**        | None |


### Workflow

Obtain original phishing email from on of the available/fastest options:

- Email Team/Email server: if there is such option
- Person who reported the attack (if it wasn't detected automatically or reported by victims)
- Victims: if they were reporting the attack

Ask for email in `.EML` format. Instructions: 

  1. Drug and drop email from Email client to Desktop
  2. Send to IR specialists by <email>
