| Title          | RA_0005_identification_find_all_phising_attack_victims                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Stage    | identification                                                            |
| Automation |<ul><li>thehive</li></ul> |
| Author    | @atc_project                                                          |
| Creation Date    | 31.01.2019                                            |
| References     | None                                  |
| Description    | Aggregated Response Action for identification of all potential victims of the phishing attack                                                               |
| Linked Response Actions |<ul><li>[RA_0026_identification_find_emails_opened](../Response_Actions/RA_0026_identification_find_emails_opened.md)</li><li>[RA_0030_identification_find_all_hosts_communicated_with_domain](../Response_Actions/RA_0030_identification_find_all_hosts_communicated_with_domain.md)</li><li>[RA_0031_identification_find_all_hosts_communicated_with_ip](../Response_Actions/RA_0031_identification_find_all_hosts_communicated_with_ip.md)</li><li>[RA_0032_identification_find_all_hosts_communicated_with_url](../Response_Actions/RA_0032_identification_find_all_hosts_communicated_with_url.md)</li><li>[RA_0033_identification_find_files_created](../Response_Actions/RA_0033_identification_find_files_created.md)</li><li>[RA_0034_identification_find_all_victims_in_security_alerts](../Response_Actions/RA_0034_identification_find_all_victims_in_security_alerts.md)</li></ul> |
| Linked Analytics | None |


### Workflow

Identify victims of the attack based on results of indicators of compromise analysis:

1. If phishing led to password harvesting form, you have to identify all users who opened malicious link with harvesting form using linked Response Actions
- Make sure that during your identification of network connections with malicious server you work with complete informatoin. For example, if corporate DNS/Proxy could be bypassed, it means that you could miss some victims. In this way you have to rely on other types of data (i.e. network flows)
- Better to check all available sources of information to be 100% sure that you've identified a potential victims
- Sometimes phising alerts could be found in AV, IPS, NGFW etc logs. Check it as well
2. If phishing led to code execution on victim host, immediately start using Generic Post Exploitation Incident Response Playbook
