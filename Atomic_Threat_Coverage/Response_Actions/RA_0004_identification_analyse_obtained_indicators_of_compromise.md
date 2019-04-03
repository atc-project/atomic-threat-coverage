| Title          | RA_0004_identification_analyse_obtained_indicators_of_compromise                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Stage    | identification                                                            |
| Automation |<ul><li>thehive</li></ul> |
| Author    | @atc_project                                                          |
| Creation Date    | 31.01.2019                                            |
| References     |<ul><li>[https://github.com/TheHive-Project/Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers)</li></ul>                                  |
| Description    | Aggregated Response Action for analysis of indicators of compromise                                                               |
| Linked Response Actions |<ul><li>[RA_0015_identification_analyse_domain_name](../Response_Actions/RA_0015_identification_analyse_domain_name.md)</li><li>[RA_0016_identification_analyse_filehash](../Response_Actions/RA_0016_identification_analyse_filehash.md)</li><li>[RA_0017_identification_analyse_ip](../Response_Actions/RA_0017_identification_analyse_ip.md)</li><li>[RA_0018_identification_analyse_macos_macho](../Response_Actions/RA_0018_identification_analyse_macos_macho.md)</li><li>[RA_0019_identification_analyse_ms_office_file](../Response_Actions/RA_0019_identification_analyse_ms_office_file.md)</li><li>[RA_0020_identification_analyse_pdf](../Response_Actions/RA_0020_identification_analyse_pdf.md)</li><li>[RA_0021_identification_analyse_unix_elf](../Response_Actions/RA_0021_identification_analyse_unix_elf.md)</li><li>[RA_0022_identification_analyse_uri](../Response_Actions/RA_0022_identification_analyse_uri.md)</li><li>[RA_0023_identification_analyse_windows_pe](../Response_Actions/RA_0023_identification_analyse_windows_pe.md)</li></ul> |
| Linked Analytics | None |


### Workflow

1. Analyse obtained indicators of compromise. Proof that they are malicious
2. Find out what exactly attacker was targeting (password harvesting, remote control etc)

This Response Action could be automated with [TheHive Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers).
