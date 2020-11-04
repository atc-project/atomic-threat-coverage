| Title             | Phishing email                                                                                                      |
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
| **Preparation**  |<ul><li>[RA1001: Practice](../Response_Actions/RA_1001_practice.md)</li><li>[RA1002: Take trainings](../Response_Actions/RA_1002_take_trainings.md)</li><li>[RA1004: Make personnel report suspicious activity](../Response_Actions/RA_1004_make_personnel_report_suspicious_activity.md)</li><li>[RA1003: Raise personnel awareness](../Response_Actions/RA_1003_raise_personnel_awareness.md)</li><li>[RA1101: Access external network flow logs](../Response_Actions/RA_1101_access_external_network_flow_logs.md)</li><li>[RA1104: Access external HTTP logs](../Response_Actions/RA_1104_access_external_http_logs.md)</li><li>[RA1106: Access external DNS logs](../Response_Actions/RA_1106_access_external_dns_logs.md)</li><li>[RA1111: Get ability to block external IP address](../Response_Actions/RA_1111_get_ability_to_block_external_ip_address.md)</li><li>[RA1113: Get ability to block external domain](../Response_Actions/RA_1113_get_ability_to_block_external_domain.md)</li><li>[RA1115: Get ability to block external URL](../Response_Actions/RA_1115_get_ability_to_block_external_url.md)</li><li>[RA1201: Get ability to list users opened email message](../Response_Actions/RA_1201_get_ability_to_list_users_opened_email_message.md)</li><li>[RA1202: Get ability to list email message receivers](../Response_Actions/RA_1202_get_ability_to_list_email_message_receivers.md)</li><li>[RA1203: Get ability to block email domain](../Response_Actions/RA_1203_get_ability_to_block_email_domain.md)</li><li>[RA1204: Get ability to block email sender](../Response_Actions/RA_1204_get_ability_to_block_email_sender.md)</li><li>[RA1205: Get ability to delete email message](../Response_Actions/RA_1205_get_ability_to_delete_email_message.md)</li><li>[RA1206: Get ability to quarantine email message](../Response_Actions/RA_1206_get_ability_to_quarantine_email_message.md)</li></ul>|
| **Identification**  |<ul><li>[RA2003: Put compromised accounts on monitoring](../Response_Actions/RA_2003_put_compromised_accounts_on_monitoring.md)</li><li>[RA2113: List hosts communicated with external domain](../Response_Actions/RA_2113_list_hosts_communicated_with_external_domain.md)</li><li>[RA2114: List hosts communicated with external IP](../Response_Actions/RA_2114_list_hosts_communicated_with_external_ip.md)</li><li>[RA2115: List hosts communicated with external URL](../Response_Actions/RA_2115_list_hosts_communicated_with_external_url.md)</li><li>[RA2201: List users opened email message](../Response_Actions/RA_2201_list_users_opened_email_message.md)</li><li>[RA2202: Collect email message](../Response_Actions/RA_2202_collect_email_message.md)</li><li>[RA2203: List email message receivers](../Response_Actions/RA_2203_list_email_message_receivers.md)</li><li>[RA2204: Make sure email message is phishing](../Response_Actions/RA_2204_make_sure_email_message_is_phishing.md)</li><li>[RA2205: Extract observables from email message](../Response_Actions/RA_2205_extract_observables_from_email_message.md)</li></ul>|
| **Containment**  |<ul><li>[RA3101: Block external IP address](../Response_Actions/RA_3101_block_external_ip_address.md)</li><li>[RA3103: Block external domain](../Response_Actions/RA_3103_block_external_domain.md)</li><li>[RA3105: Block external URL](../Response_Actions/RA_3105_block_external_url.md)</li><li>[RA3201: Block domain on email](../Response_Actions/RA_3201_block_domain_on_email.md)</li><li>[RA3202: Block sender on email](../Response_Actions/RA_3202_block_sender_on_email.md)</li><li>[RA3203: Quarantine email message](../Response_Actions/RA_3203_quarantine_email_message.md)</li></ul>|
| **Eradication**  |<ul><li>[RA4001: Report incident to external companies](../Response_Actions/RA_4001_report_incident_to_external_companies.md)</li><li>[RA4201: Delete email message](../Response_Actions/RA_4201_delete_email_message.md)</li></ul>|
| **Recovery**  |<ul><li>[RA5101: Unblock blocked IP](../Response_Actions/RA_5101_unblock_blocked_ip.md)</li><li>[RA5102: Unblock blocked domain](../Response_Actions/RA_5102_unblock_blocked_domain.md)</li><li>[RA5103: Unblock blocked URL](../Response_Actions/RA_5103_unblock_blocked_url.md)</li><li>[RA5201: Unblock domain on email](../Response_Actions/RA_5201_unblock_domain_on_email.md)</li><li>[RA5202: Unblock sender on email](../Response_Actions/RA_5202_unblock_sender_on_email.md)</li><li>[RA5203: Restore quarantined email message](../Response_Actions/RA_5203_restore_quarantined_email_message.md)</li></ul>|
| **Lessons learned**  |<ul><li>[RA6001: Develop incident report](../Response_Actions/RA_6001_develop_incident_report.md)</li><li>[RA6002: Conduct lessons learned exercise](../Response_Actions/RA_6002_conduct_lessons_learned_exercise.md)</li></ul>|

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

##### Make sure that personnel will report suspicious activity i.e. suspicious emails,  links, files, activity on their computers, etc


Develop a simplified, company wide-known way to contact IR team in case of suspicious activity on the user system.  
Make sure that the personnel is aware of it, can and will use it.  

##### Raise personnel awareness regarding phishing, ransomware, social engineering,  and other attacks that involve user interaction


Train users to to be aware of access or manipulation attempts by an adversary to reduce the risk of 
successful spearphishing, social engineering, and other techniques that involve user interaction.

##### Make sure you have access to external communication Network Flow logs


Make sure that there is a collection of Network Flow logs for external communication (from corporate assets to the Internet) configured.  
If there is no option to configure it on a network device, you can install a special software on each endpoint and collect it from them.  

Warning:  

- There is a feature called ["NetFlow Sampling"](https://www.plixer.com/blog/how-accurate-is-sampled-netflow/), that eliminates the value of the Network Flow logs for some of the tasks, such as "check if some host communicated to an external IP". Make sure it's disabled or you have an alternative way to collect Network Flow logs  

##### Make sure you have access to external communication HTTP logs


Make sure that there is a collection of HTTP connections logs for external communication (from corporate assets to the Internet) configured.  

##### Make sure you have access to external communication DNS logs


Make sure that there is a collection of DNS logs for external communication (from corporate assets to the Internet) configured.  
If there is no option to configure it on a network device/DNS Server, you can install a special software on each endpoint and collect it from them.  

Warning:  

- Make sure that there are both DNS query and answer logs collected. It's quite hard to configure such a collection on MS Windows DNS server and ISC BIND. Sometimes it much easier to use 3rd party solutions to fulfill this requirement.  
- Make sure that DNS traffic to the external (public) DNS servers is blocked by the Border Firewall. This way, corporate DNS servers is the only place assets can resolve the domain names.  

##### Make sure you have the ability to block an external IP address from being accessed by corporate assets


Make sure you have the ability to create a policy rule in one of the listed Mitigation Systems that will you to block an external IP address from being accessed by corporate assets.  

Warning:  

- Make sure that using the listed systems (1 or multiple) you can control access to the internet of all assets in the infrastructure. In some cases, you will need a guaranteed way to block an external IP address from being accessed by corporate assets completely. If some of the assets are not under the management of the listed Mitigation Systems, (so they can access the internet bypassing these systems), you will not be able to fully achieve the final objective of the Response Action.  

##### Make sure you have the ability to block an external domain name from being accessed by corporate assets


Make sure you have the ability to create a policy rule or a specific configuration in one of the listed Mitigation Systems that will you to block an external domain name from being accessed by corporate assets.  

Warning:  

- Make sure that using the listed systems (1 or multiple) you can control access to the internet of all assets in the infrastructure. In some cases, you will need a guaranteed way to block an external domain name from being accessed by corporate assets completely. If some of the assets are not under the management of the listed Mitigation Systems, (so they can access the internet bypassing these systems), you will not be able to fully achieve the final objective of the Response Action.  

##### Make sure you have the ability to block an external URL from being accessed by corporate assets


Make sure you have the ability to create a policy rule or a specific configuration in one of the listed Mitigation Systems that will you to block an external URL from being accessed by corporate assets.  

Warning:  

- Make sure that using the listed systems (1 or multiple) you can control access to the internet of all assets in the infrastructure. In some cases, you will need a guaranteed way to block an external URL from being accessed by corporate assets completely. If some of the assets are not under the management of the listed Mitigation Systems, (so they can access the internet bypassing these systems), you will not be able to fully achieve the final objective of the Response Action.  

##### Make sure you have the ability to list users who opened a particular email message


Make sure you have the ability to list users who opened/read a particular email message using the Email Server's functionality.

##### Make sure you have the ability to list receivers of a particular email message


Make sure you have the ability to list receivers of a particular email message using the Email Server's functionality.

##### Make sure you have the ability to block an email domain


Make sure you have the ability to block an email domain on an Email Server using its native filtering functionality.  

##### Make sure you have the ability to block an email sender


Make sure you have the ability to block an email sender on an Email Server using its native filtering functionality.  

##### Make sure you have the ability to delete an email message


Make sure you have the ability to delete an email message from an Email Server and users' email boxes using its native functionality.

##### Make sure you have the ability to quarantine an email message


Make sure you have the ability to quarantine an email message on an Email Server using its native functionality.  

#### Identification

##### Put (potentially) compromised accounts on monitoring

Start monitoring for authentification attempts and all potentially harmful actions from (potentially) compromised accounts.  
Look for anomalies, unusual network connections, unusual geolocation/time of work, actions that were never executed before.  
Keep in touch with the real users and, in case of need, ask them if they executing some suspicious actions by themselves or not.  

##### List hosts communicated with an external domain


List hosts communicated with an external domain using the most efficient way.  

##### List hosts communicated with an external IP address


List hosts communicated with an external IP address using the most efficient way.  

##### List hosts communicated with an external URL


List hosts communicated with an external URL using the most efficient way.  
##### List users that have opened am email message


List users who opened/read a particular email message using the Email Server's functionality.  

##### Collect an email message

Collect an email message using the most appropriate option:  

- Email Team/Email server: if there is such option  
- The person that reported the attack (if it wasn't detected automatically or reported by victims)  
- Victims: if they reported the attack  
- Following the local computer forensic evidence collection procedure, if the situation requires it

Ask for the email in `.EML` format. Instructions:  

  1. Drug and drop email from Email client to Desktop  
  2. Archive with password "infected" and send to IR specialists by email  

##### List receivers of a particular email message


List receivers of a particular email message using the Email Server's functionality.  
##### Make sure that an email message is a phishing attack

Check an email and its metadata for evidences of phishing attack:  

- **Impersonalisation attempts**: sender is trying to identify himself as somebody he is not  
- **Suspicious askings or offers**: download "invoice", click on link with something important etc  
- **Psychological manipulations**: invoking a sense of urgency or fear is a common phishing tactic  
- **Spelling mistakes**: legitimate messages usually don't have spelling mistakes or poor grammar  

Explore references of the article to make yourself familiar with phishing attacks history and examples.  

##### Extract observables from an email message

Extract the data for further response steps:  

- attachments (using munpack tool: `munpack email.eml`)  
- from, to, cc  
- subject of the email  
- received servers path  
- list of URLs from the text content of the mail body and attachments  

This Response Action could be automated with [TheHive EmlParser](https://blog.thehive-project.org/2018/07/31/emlparser-a-new-cortex-analyzer-for-eml-files/).  

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


Block an email sender on an Email Server using its native filtering functionality.  

##### Quarantine an email message


Quarantine an email message on an Email Server using its native functionality.  

#### Eradication

##### Report incident to external companies

Report incident to external security companites, i.e. [National Computer Security Incident Response Teams (CSIRTs)](https://www.sei.cmu.edu/education-outreach/computer-security-incident-response-teams/national-csirts/).  
Provide all Indicators of Compromise and Indicators of Attack that have been observed.  

A phishing attack could be reported to:  

1. [National Computer Security Incident Response Teams (CSIRTs)](https://www.sei.cmu.edu/education-outreach/computer-security-incident-response-teams/national-csirts/)  
2. [U.S. government-operated website](http://www.us-cert.gov/nav/report_phishing.html)  
3. [Anti-Phishing Working Group (APWG)](http://antiphishing.org/report-phishing/)  
4. [Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/?hl=en)  
5. [The FBI's Intenet Crime Complaint Center (IC3)](https://www.ic3.gov/default.aspx)  

This Response Action could be automated with [TheHive and MISP integration](https://blog.thehive-project.org/2017/06/19/thehive-cortex-and-misp-how-they-all-fit-together/).  

##### Delete an email message from an Email Server and users' email boxes

Delete an email message from an Email Server and users' email boxes using its native functionality.

#### Recovery

##### Unblock a blocked IP address


Unblock a blocked IP address in the system(s) used to block it.  

##### Unblock a blocked domain name


Unblock a blocked domain name in the system(s) used to block it.  

##### Unblock a blocked URL


Unblock a blocked URL in the system(s) used to block it.  

##### Unblock a domain on email


Unblock an email domain on an Email Server using its native functionality.  

##### Unblock a sender on email


Unblock an email sender on an Email Server using its native functionality.  

##### Restore a quarantined email message


Restore a quarantined email message on an Email Server using its native functionality.  

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
You need to answer some basic questions, using developed incident report:  

- What happened?  
- What did we do well?  
- What could we have done better?  
- What will we do differently next time?  

The incident report is the key to improvements.  














