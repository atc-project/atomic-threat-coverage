| Title             | RP_0001_phishing_email                                                                                                      |
|:------------------|:-----------------------------------------------------------------------------------------------------------------|
| **Description**   | Response playbook for Phishing Email case   |
| **Author**        | @atc_project        |
| **Creation Date** | 31.01.2019 |
| **Severity**      | M      |
| **TLP**           | AMBER           |
| **PAP**           | WHITE           |
| **ATT&amp;CK Tactic**  |<ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>|
| **ATT&amp;CK Technique**  |<ul><li>[T1193: Spearphishing Attachment](https://attack.mitre.org/tactics/T1193)</li><li>[T1192: Spearphishing Link](https://attack.mitre.org/tactics/T1192)</li></ul>|
| **Tags**          |<ul><li>phishing</li></ul> |
| **Identification**  |<ul><li>[RA_0001_identification_get_original_email](../Response_Actions/RA_0001_identification_get_original_email.md)</li><li>[RA_0002_identification_extract_observables_from_email](../Response_Actions/RA_0002_identification_extract_observables_from_email.md)</li><li>[RA_0003_identification_make_sure_email_is_a_phishing](../Response_Actions/RA_0003_identification_make_sure_email_is_a_phishing.md)</li><li>[RA_0004_identification_analyse_obtained_indicators_of_compromise](../Response_Actions/RA_0004_identification_analyse_obtained_indicators_of_compromise.md)</li><li>[RA_0005_identification_find_all_phishing_attack_victims](../Response_Actions/RA_0005_identification_find_all_phishing_attack_victims.md)</li><li>[RA_0040_identification_put_on_monitoring_compromised_accounts](../Response_Actions/RA_0040_identification_put_on_monitoring_compromised_accounts.md)</li></ul>|
| **Containment**  |<ul><li>[RA_0006_containment_block_domain_on_email](../Response_Actions/RA_0006_containment_block_domain_on_email.md)</li><li>[RA_0028_containment_block_threat_on_network_level](../Response_Actions/RA_0028_containment_block_threat_on_network_level.md)</li></ul>|
| **Eradication**  |<ul><li>[RA_0010_eradication_delete_malicious_emails](../Response_Actions/RA_0010_eradication_delete_malicious_emails.md)</li><li>[RA_0011_eradication_revoke_compromised_credentials](../Response_Actions/RA_0011_eradication_revoke_compromised_credentials.md)</li><li>[RA_0012_eradication_report_phishing_attack_to_external_companies](../Response_Actions/RA_0012_eradication_report_phishing_attack_to_external_companies.md)</li></ul>|
| **Lessons Learned**  |<ul><li>[RA_0013_lessons_learned_develop_incident_report](../Response_Actions/RA_0013_lessons_learned_develop_incident_report.md)</li><li>[RA_0014_lessons_learned_conduct_lessons_learned_exercise](../Response_Actions/RA_0014_lessons_learned_conduct_lessons_learned_exercise.md)</li></ul>|


### Workflow

1. Execute Response Actions step by step. Some of them directly connected, which means you will not be able to move forward not finishing previous step
2. Start executing containment and eradication stages concurrently with next identification steps, as soon as you will receive infomration about malicious hosts
3. If phishing led to code execution or remote access to victim host, immediately start executing Generic Post Exploitation Incident Response Playbook
4. Save all timestamps of implemented actions in Incident Report draft on the fly, it will save a lot of time



#### Identification

##### Obtain the original phishing email

Obtain original phishing email from on of the available/fastest options:

- Email Team/Email server: if there is such option
- Person who reported the attack (if it wasn't detected automatically or reported by victims)
- Victims: if they were reporting the attack

Ask for email in `.EML` format. Instructions: 

  1. Drug and drop email from Email client to Desktop
  2. Send to IR specialists by <email>

##### Extract all observables from the original phishing email

Extract the data for further response steps:

- attachments (using munpack tool: `munpack email.eml`)
- from, to, cc
- subject of the email
- received servers path
- list of URLs from the text content of the mail body and attachments

This Response Action could be automated with [TheHive EmlParser](https://blog.thehive-project.org/2018/07/31/emlparser-a-new-cortex-analyzer-for-eml-files/).

##### Make sure the email is a phishing attack

Check email and its metadata for evidences of phishing attack:

- **Impersonalisation attempts**: sender is trying to identify himself as somebody he is not
- **Suspicious askings or offers**: download "invoice", click on link with something important etc
- **Psychological manipulations**: invoking a sense of urgency or fear is a common phishing tactic
- **Spelling mistakes**: legitimate messages usually don't have spelling mistakes or poor grammar

Explore references of the article to make yourself familiar with phishing attacks history and examples.

##### Aggregated Response Action for analysis of indicators of compromise

1. Analyse obtained indicators of compromise. Proof that they are malicious
2. Find out what exactly attacker was targeting (password harvesting, remote control etc)

This Response Action could be automated with [TheHive Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers).

##### Aggregated Response Action for identification of all potential victims of the phishing attack


Identify victims of the attack based on results of indicators of compromise analysis:

1. If phishing led to password harvesting form, you have to identify all users who opened malicious link with harvesting form using linked Response Actions
- Make sure that during your identification of network connections with malicious server you work with complete informatoin. For example, if corporate DNS/Proxy could be bypassed, it means that you could miss some victims. In this way you have to rely on other types of data (i.e. network flows)
- Better to check all available sources of information to be 100% sure that you've identified a potential victims
- Sometimes phishing alerts could be found in AV, IPS, NGFW etc logs. Check it as well
2. If phishing led to code execution on victim host, immediately start using Generic Post Exploitation Incident Response Playbook

##### Put (potentially) compromised accounts on monitoring

Start monitoring for authentification attempts and all potentially harmful actions from potentially compromised accounts.
Look for anomalies, strange network connections, unusual geolocation/time of work, actions which were never executed before.
Keep in touch with real users and in case of need ask them if they executing these actions by themselves or not.

#### Containment

##### Block a phishing attack source on Email-server level

Block malicious sender (or entire domain, if possible) on Email Server using native filtering functionality.

##### Block threats on the Network Level

Develop plan of containment depends on connditions and network architecture, execute it and make sure you have fully blocked threat on network level.

#### Eradication

##### Delete malicious emails from a Email Server and users' email boxes

Delete malicious emails from Email Server and users' email boxes using native Email Server functionality.

##### Response Action for revokation of compromised credentials

On this step you supposed to know what kind of credentials have beed compromised.
You need to revoke them in your Identity and Access Management system where they were created (like, Windows AD) using native functionality.
Warning:
- If adversary has generated Golden Ticket in Windows Domain/forest, you have to revoke KRBTGT Account password **twice** for each domain in a forest and proceed monitor malicious activity for next 20 minutes (Domain Controller KDC service doesn’t perform validate the user account until the TGT is older than 20 minutes old)

##### Report phishing attack to external companies

Report phishing attack to external companites:

1. [National Computer Security Incident Response Teams (CSIRTs)](https://www.sei.cmu.edu/education-outreach/computer-security-incident-response-teams/national-csirts/)
2. [U.S. government-operated website](http://www.us-cert.gov/nav/report_phishing.html)
3. [Anti-Phishing Working Group (APWG)](http://antiphishing.org/report-phishing/)
4. [Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en)
5. [The FBI's Intenet Crime Complaint Center (IC3)](https://www.ic3.gov/default.aspx)

This Response Action could be automated with [TheHive and MISP integration](https://blog.thehive-project.org/2017/06/19/thehive-cortex-and-misp-how-they-all-fit-together/).



#### Lessons learned

##### Develop Incident Resposne Report

Develop Incident Report using your corporate template.

It should include:

1. Executive Summary with short description of damage, actions taken, root cause, and key metrics (Time To Detect, Time To Respond, Time To Recover)
2. Detailed timeline of adversary actions, mapped to [ATT&CK tactics](https://attack.mitre.org/tactics/enterprise/) (you can use [Kill Chain](https://en.wikipedia.org/wiki/Kill_chain), but 95% of all actions will be in Actions On Objective stage, which is not really representative, meaningfull and usefull)
3. Detailed timeline of actions taken by Incident Responders
4. Root Cause Analysis and Recommendations for improvements based on its conclusion
5. List of specialists involved into Incident Response with their roles

##### Conduct Lessons Learned exercise

This Lessons Learned phase evaluates the team's performance through each step. 
Basically, this takes the incident report and answers some basic questions:

- What happened?
- What did we do well?
- What could we have done better?
- What will we do differently next time?

The goal of the Lessons Learned phase is to discover how to make the next incident response go faster, smoother, or ideally never happen at all.
Keep in mind that incident report is a key. If, for example, Time To Respond looks horrible, it was caused by some problem.
The only way to solve it is to bring it up and start working on it.














