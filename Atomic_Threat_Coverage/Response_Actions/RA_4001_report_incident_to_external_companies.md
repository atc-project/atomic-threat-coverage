| Title                       | Report incident to external companies         |
|:---------------------------:|:--------------------|
| **ID**                      | RA4001            |
| **Description**             | Report incident to external companies   |
| **Author**                  | @atc_project        |
| **Creation Date**           | 2019/01/31 |
| **Category**                | General      |
| **Stage**                   |[RS0004: Eradication](../Response_Stages/RS0004.md)| 
| **Automation** |<ul><li>thehive</li></ul>|
| **References** |<ul><li>[https://www.antiphishing.org/report-phishing/](https://www.antiphishing.org/report-phishing/)</li><li>[https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en](https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en)</li><li>[https://www.ic3.gov/default.aspx](https://www.ic3.gov/default.aspx)</li><li>[http://www.us-cert.gov/nav/report_phishing.html](http://www.us-cert.gov/nav/report_phishing.html)</li><li>[https://blog.thehive-project.org/2017/06/19/thehive-cortex-and-misp-how-they-all-fit-together/](https://blog.thehive-project.org/2017/06/19/thehive-cortex-and-misp-how-they-all-fit-together/)</li><li>[https://www.sei.cmu.edu/education-outreach/computer-security-incident-response-teams/national-csirts/](https://www.sei.cmu.edu/education-outreach/computer-security-incident-response-teams/national-csirts/)</li><li>[https://www.crowdstrike.com/blog/indicators-attack-vs-indicators-compromise/](https://www.crowdstrike.com/blog/indicators-attack-vs-indicators-compromise/)</li><li>[https://mitre.github.io/unfetter/about/](https://mitre.github.io/unfetter/about/)</li></ul>|

### Workflow

Report incident to external security companites, i.e. [National Computer Security Incident Response Teams (CSIRTs)](https://www.sei.cmu.edu/education-outreach/computer-security-incident-response-teams/national-csirts/).  
Provide all Indicators of Compromise and Indicators of Attack that have been observed.  

A phishing attack could be reported to:  

1. [National Computer Security Incident Response Teams (CSIRTs)](https://www.sei.cmu.edu/education-outreach/computer-security-incident-response-teams/national-csirts/)  
2. [U.S. government-operated website](http://www.us-cert.gov/nav/report_phishing.html)  
3. [Anti-Phishing Working Group (APWG)](http://antiphishing.org/report-phishing/)  
4. [Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en)  
5. [The FBI's Intenet Crime Complaint Center (IC3)](https://www.ic3.gov/default.aspx)  

This Response Action could be automated with [TheHive and MISP integration](https://blog.thehive-project.org/2017/06/19/thehive-cortex-and-misp-how-they-all-fit-together/).  
