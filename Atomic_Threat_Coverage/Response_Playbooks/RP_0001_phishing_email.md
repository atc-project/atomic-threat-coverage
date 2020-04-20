| Title             |  Phishing email                                                                                                      |
|:-----------------:|:-----------------------------------------------------------------------------------------------------------------|
| **ID**            | RP0001            |
| **Description**   | Response playbook for Phishing Email case   |
| **Author**        | @atc_project        |
| **Creation Date** | 31.01.2019 |
| **Severity**      | M      |
| **TLP**           | AMBER           |
| **PAP**           | WHITE           |
| **ATT&amp;CK Tactic**  |<ul><li>[TA0001: Initial Access](https://attack.mitre.org/tactics/TA0001)</li></ul>|
| **ATT&amp;CK Technique**  |<ul><li>[T1193: Spearphishing Attachment](https://attack.mitre.org/tactics/T1193)</li><li>[T1192: Spearphishing Link](https://attack.mitre.org/tactics/T1192)</li></ul>|
| **Tags**          | <ul><li>phishing</li></ul> |
| **Preparation**  |<ul><li>[RA1101: Practice](../Response_Actions/RA_1101_practice.md)</li><li>[RA1102: Take trainings](../Response_Actions/RA_1102_take_trainings.md)</li><li>[RA1104: Make personnel report suspicious activity](../Response_Actions/RA_1104_make_personnel_report_suspicious_activity.md)</li><li>[RA1103: Raise personnel awareness](../Response_Actions/RA_1103_raise_personnel_awareness.md)</li><li>[RA1301: Get ability to list users opened email](../Response_Actions/RA_1301_get_ability_to_list_users_opened_email.md)</li><li>[RA1302: Get ability to list users received email](../Response_Actions/RA_1302_get_ability_to_list_users_received_email.md)</li><li>[RA1303: Get ability to block email domain](../Response_Actions/RA_1303_get_ability_to_block_email_domain.md)</li><li>[RA1304: Get ability to block email sender](../Response_Actions/RA_1304_get_ability_to_block_email_sender.md)</li><li>[RA1305: Get ability to delete email](../Response_Actions/RA_1305_get_ability_to_delete_email.md)</li><li>[RA1201: Access external network flow logs](../Response_Actions/RA_1201_access_external_network_flow_logs.md)</li><li>[RA1204: Access external HTTP logs](../Response_Actions/RA_1204_access_external_http_logs.md)</li><li>[RA1206: Access external DNS logs](../Response_Actions/RA_1206_access_external_dns_logs.md)</li><li>[RA1211: Get ability to block external IP address](../Response_Actions/RA_1211_get_ability_to_block_external_ip_address.md)</li><li>[RA1213: Get ability to block external domain](../Response_Actions/RA_1213_get_ability_to_block_external_domain.md)</li><li>[RA1215: Get ability to block external URL](../Response_Actions/RA_1215_get_ability_to_block_external_url.md)</li></ul>|
| **Identification**  |<ul><li>[RA2302: Get original email](../Response_Actions/RA_2302_get_original_email.md)</li><li>[RA2301: List users opened email](../Response_Actions/RA_2301_list_users_opened_email.md)</li><li>[RA2303: List email receivers](../Response_Actions/RA_2303_list_email_receivers.md)</li><li>[RA2104: Make sure email is a phishing](../Response_Actions/RA_2304_make_sure_email_is_a_phishing.md)</li><li>[RA2101: Extract observables from email](../Response_Actions/RA_2305_extract_observables_from_email.md)</li><li>[RA2103: Put compromised accounts on monitoring](../Response_Actions/RA_2103_put_compromised_accounts_on_monitoring.md)</li><li>[RA2213: List hosts communicated with external domain](../Response_Actions/RA_2213_list_hosts_communicated_with_external_domain.md)</li><li>[RA2214: List hosts communicated with external ip.](../Response_Actions/RA_2214_list_hosts_communicated_with_external_ip.md)</li><li>[RA2215: List hosts communicated with external URL](../Response_Actions/RA_2215_list_hosts_communicated_with_external_url.md)</li></ul>|
| **Containment**  |<ul><li>[RA3201: Block external IP address](../Response_Actions/RA_3201_block_external_ip_address.md)</li><li>[RA3203: Block external domain](../Response_Actions/RA_3203_block_external_domain.md)</li><li>[RA3205: Block external URL](../Response_Actions/RA_3205_block_external_url.md)</li><li>[RA3301: Block domain on email](../Response_Actions/RA_3301_block_domain_on_email.md)</li><li>[RA3302: Block sender on email](../Response_Actions/RA_3302_block_sender_on_email.md)</li></ul>|
| **Eradication**  |<ul><li>[RA4301: Delete malicious emails](../Response_Actions/RA_4301_delete_malicious_emails.md)</li><li>[RA4701: Revoke compromised credentials](../Response_Actions/RA_4701_revoke_compromised_credentials.md)</li><li>[RA4101: Report phishing attack to external companies](../Response_Actions/RA_4101_report_phishing_attack_to_external_companies.md)</li></ul>|
| **Lessons learned**  |<ul><li>[RA6101: Develop incident report](../Response_Actions/RA_6101_develop_incident_report.md)</li><li>[RA6102: Conduct lessons learned exercise](../Response_Actions/RA_6102_conduct_lessons_learned_exercise.md)</li></ul>|

### Workflow
 
1. Execute Response Actions step by step. Some of them directly connected, which means you will not be able to move forward not finishing the previous step. Some of them are redundant, as those that are related to the blocking a threat using network filtering systems (containment stage)
2. Start executing containment and eradication stages concurrently with next identification steps, as soon as you will receive information about malicious hosts
3. If phishing led to code execution or remote access to victim host, immediately start executing Generic Post Exploitation Incident Response Playbook
4. Save all timestamps of implemented actions in Incident Report draft on the fly, it will save a lot of time



#### Preparation

##### Practice in the real environment. Sharpen Response Actions within your organization

Make sure that most of the Response Action has been performed on an internal exercise by your Incident Response Team.  
You need to make sure that when an Incident will happen, the team will not just try to follow the playbooks they see first time in their lives, but will be able to quickly execute the actual steps in **your environment**, i.e. blocking an IP address or a domain name.  

##### Take training courses to gain relevant knowledge

> We do not rise to the level of our expectations. We fall to the level of our training.  

Here are some relevant training courses that will help you in the Incident Response activities:  

1. [Investigation Theory](https://chrissanders.org/training/investigationtheory/) by Chris Sanders. We recommend you to have it as a mandatory training for every member of your Incident Response team  
2. [Offensive Security](https://www.offensive-security.com/courses-and-certifications/) trainings. We recommend [PWK](https://www.offensive-security.com/pwk-oscp/) to begin with  
3. [SANS Digital Forensics & Incident Response](https://digital-forensics.sans.org/training/courses) trainings  

Offensive Security trainings are in the list because to fight a threat, you need to understand their motivation, tactics, and techniques.  

At the same time, we assume that you already have a strong technical background in fundamental disciplines — Networking, Operating Systems, and Programming.  

##### Develop a simplified, company wide-known way to contact IR team in case of suspicious activity on the user system. Make sure that the personnel is aware of it, can and will use it


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Raise personnel awareness regarding phishing, ransomware, social engineering, and other attacks


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Make sure you have the ability to list users who opened a particular email


Description of the workflow for the Response Action in markdown format.
Here newlines will be saved.

##### Make sure you have the ability to list users who received a particular email


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Make sure you have the ability to block an email domain


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Make sure you have the ability to block an email sender


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Make sure you have the ability to delete an email


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Make sure you have access to external communication Network Flow logs


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Make sure you have access to external communication HTTP logs


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Make sure you have access to external communication DNS logs


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Make sure you can block an external IP address from being accessed by corporate assets


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Make sure you can block an external domain name from being accessed by corporate assets


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Make sure you can block an external URL from being accessed by corporate assets


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

#### Identification

##### Obtain the original phishing email

Obtain the original email from one of the available/fastest options:  

- Email Team/Email server: if there is such option  
- Person who reported the attack (if it wasn't detected automatically or reported by victims)  
- Victims: if they reported the attack  

Ask for the email in `.EML` format. Instructions:  

  1. Drug and drop email from Email client to Desktop  
  2. Archive with password "infected" and send to IR specialists by email  

##### Response Action for 


Description of how to handle multiple Response Actions (if it is an aggregated Response Action) or workflow for single Response Action in markdown format.
Here newlines will be saved.  

##### List receivers of a specific email


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

##### Make sure an email is a phishing attack

Check an email and its metadata for evidences of phishing attack:  

- **Impersonalisation attempts**: sender is trying to identify himself as somebody he is not  
- **Suspicious askings or offers**: download "invoice", click on link with something important etc  
- **Psychological manipulations**: invoking a sense of urgency or fear is a common phishing tactic  
- **Spelling mistakes**: legitimate messages usually don't have spelling mistakes or poor grammar  

Explore references of the article to make yourself familiar with phishing attacks history and examples.  

##### Extract all observables from the original phishing email

Extract the data for further response steps:  

- attachments (using munpack tool: `munpack email.eml`)  
- from, to, cc  
- subject of the email  
- received servers path  
- list of URLs from the text content of the mail body and attachments  

This Response Action could be automated with [TheHive EmlParser](https://blog.thehive-project.org/2018/07/31/emlparser-a-new-cortex-analyzer-for-eml-files/).  

##### Put (potentially) compromised accounts on monitoring

Start monitoring for authentification attempts and all potentially harmful actions from (potentially) compromised accounts.  
Look for anomalies, unusual network connections, unusual geolocation/time of work, actions that were never executed before.  
Keep in touch with the real users and, in case of need, ask them if they executing some suspicious actions by themselves or not.  

##### Response Action for 


Description of the workflow for the Response Action in markdown format.
Here newlines will be saved.

##### Response Action for 


Description of the workflow for the Response Action in markdown format.
Here newlines will be saved.

##### Response Action for


Description of the workflow for the Response Action in markdown format.
Here newlines will be saved.

#### Containment

##### Block an external IP address from being accessed by corporate assets


Block an external IP address from being accessed by corporate assets, using the most efficient way.  

Warning:  

- Be careful blocking IP addresses. Make sure it's not a cloud provider or a hoster. If you would like to block something that is hosted on a well-known cloud provider or on a big hoster IP address, you should block (if applicable) a specific URL using alternative Response Action   

##### Block an external domain name from being accessed by corporate assets


Block an external domain name from being accessed by corporate assets, using the most efficient way.  

Warning:  

- Be careful blocking doman names. Make sure it's not a cloud provider or a hoster. If you would like to block something that is hosted on a well-known cloud provider or on a big hoster doman, you should block (if applicable) a specific URL using alternative Response Action   

##### Block an external URL from being accessed by corporate assets


Block an external URL from being accessed by corporate assets, using the most efficient way.  

##### Block a domain name on an Email server

Block a domain name on an Email Server using its native filtering functionality.  

##### Block an email sender on the Email-server


Description of the workflow for single Response Action in markdown format.
Here newlines will be saved.

#### Eradication

##### Delete malicious emails from a Email Server and users' email boxes

Delete email from an Email Server and users' email boxes using its native functionality.

##### Response Action for compromised credentials revocation

On this step, you supposed to know what kind of credentials have been compromised.  
You need to revoke them in your Identity and Access Management system where they were created (i.e. Windows AD) using native functionality.  

Warning:  

- If the adversary has generated Golden Ticket in Windows Domain/forest, you have to revoke KRBTGT Account password **twice** for each domain in a forest and proceed to monitor malicious activity for next 20 minutes (Domain Controller KDC service doesn’t perform validate the user account until the TGT is older than 20 minutes old)

##### Report phishing attack to external companies

Report phishing attack to external companites:  

1. [National Computer Security Incident Response Teams (CSIRTs)](https://www.sei.cmu.edu/education-outreach/computer-security-incident-response-teams/national-csirts/)  
2. [U.S. government-operated website](http://www.us-cert.gov/nav/report_phishing.html)  
3. [Anti-Phishing Working Group (APWG)](http://antiphishing.org/report-phishing/)  
4. [Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en)  
5. [The FBI's Intenet Crime Complaint Center (IC3)](https://www.ic3.gov/default.aspx)  

This Response Action could be automated with [TheHive and MISP integration](https://blog.thehive-project.org/2017/06/19/thehive-cortex-and-misp-how-they-all-fit-together/).  



#### Lessons learned

##### Develop the incident report

Develop the Incident Report using your corporate template.  

It should include:  

1. Executive Summary with a short description of damage, actions taken, root cause, and key metrics (Time To Detect, Time To Respond, Time To Recover etc)  
2. Detailed timeline of adversary actions mapped to [ATT&CK tactics](https://attack.mitre.org/tactics/enterprise/) (you can use the [Kill Chain](https://en.wikipedia.org/wiki/Kill_chain), but most probably most of the actions will be in Actions On Objective stage, which is not very representative and useful)  
3. Detailed timeline of actions taken by Incident Response Team  
4. Root Cause Analysis and Recommendations for improvements based on its conclusion  
5. List of specialists involved in Incident Response with their roles  

##### Conduct Lessons Learned exercise

The Lessons Learned phase evaluates the team's performance through each step. 
The goal of the phase is to discover how to improve the incident response process.  
Basically, you need to answer some basic questions, using the incident report:  

- What happened?  
- What did we do well?  
- What could we have done better?  
- What will we do differently next time?  

Keep in mind that the incident report is the key.  
For example, if Time To Respond is too long, it was caused by some problem.  
The only way to solve it is to bring it up and start working on it.  














