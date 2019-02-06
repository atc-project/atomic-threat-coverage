| Title          | RP_0001_phishing_email                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Description    | Response playbook for Phishing Email case.                                        	|
| Tags    | <ul><li>attack.initial_access</li><li>attack.t1193</li><li>attack.t1192</li><li>phishinng</li></ul>    	|
| Severity    | M                                             		|
| TLP    | AMBER                                                            |
| PAP    | WHITE                                                            |
| Author    | Daniil Yugoslavskiy                                        				|
| Creation Date    | 31.01.2019                                       	|
| Identification | <ul><li>[RA_0001_identification_get_original_email](../Response_Actions/RA_0001_identification_get_original_email.md)</li><li>[RA_0002_identification_extract_observables_from_email](../Response_Actions/RA_0002_identification_extract_observables_from_email.md)</li><li>[RA_0003_identification_make_sure_email_is_a_phising](../Response_Actions/RA_0003_identification_make_sure_email_is_a_phising.md)</li><li>[RA_0004_identification_analyse_obtained_indicators_of_compromise](../Response_Actions/RA_0004_identification_analyse_obtained_indicators_of_compromise.md)</li><li>[RA_0005_identification_find_all_phising_attack_victims](../Response_Actions/RA_0005_identification_find_all_phising_attack_victims.md)</li><li>[RA_0040_identification_put_on_monitoring_compromised_accounts](../Response_Actions/RA_0040_identification_put_on_monitoring_compromised_accounts.md)</li></ul> |
| Containment | <ul><li>[RA_0006_containment_block_domain_on_email](../Response_Actions/RA_0006_containment_block_domain_on_email.md)</li><li>[RA_0028_containment_block_threat_on_network_level](../Response_Actions/RA_0028_containment_block_threat_on_network_level.md)</li></ul> |
| Eradication | <ul><li>[RA_0010_eradication_delete_malicious_emails](../Response_Actions/RA_0010_eradication_delete_malicious_emails.md)</li><li>[RA_0011_eradication_revoke_compromised_credentials](../Response_Actions/RA_0011_eradication_revoke_compromised_credentials.md)</li><li>[RA_0012_eradication_report_phishing_attack_to_external_companies](../Response_Actions/RA_0012_eradication_report_phishing_attack_to_external_companies.md)</li></ul> |
| Recovery | <ul></ul> |
| Lessons Learned | <ul><li>[RA_0013_lessons_learned_develop_incident_report](../Response_Actions/RA_0013_lessons_learned_develop_incident_report.md)</li><li>[RA_0014_lessons_learned_conduct_lessons_learned_exercise](../Response_Actions/RA_0014_lessons_learned_conduct_lessons_learned_exercise.md)</li></ul> |

### Workflow

```
1. Execute Response Actions step by step. Some of them directly connected, which means you will not be able to move forward not finishing previous step
2. Start executing containment and eradication stages concurrently with next identification steps, as soon as you will receive infomration about malicious hosts
3. If phishing led to code execution or remote access to victim host, immediately start executing Generic Post Exploitation Incident Response Playbook
4. Save all timestamps of implemented actions in Incident Report draft on the fly, it will save a lot of time

```