| Title                | Password Dumper Activity on LSASS                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unkown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/jackcr/status/807385668833968128](https://twitter.com/jackcr/status/807385668833968128)</li></ul>  |
| Author               |  Author of this Detection Rule haven't introduced himself  |


## Detection Rules

### Sigma rule

```
title: Password Dumper Activity on LSASS
id: aa1697b7-d611-4f9a-9cb2-5125b4ccfd5c
description: Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN
status: experimental
references:
    - https://twitter.com/jackcr/status/807385668833968128
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4656
        ProcessName: 'C:\Windows\System32\lsass.exe'
        AccessMask: '0x705'
        ObjectType: 'SAM_DOMAIN'
    condition: selection
falsepositives:
    - Unkown
level: high

```





### splunk
    
```
(EventID="4656" ProcessName="C:\\\\Windows\\\\System32\\\\lsass.exe" AccessMask="0x705" ObjectType="SAM_DOMAIN")
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Password Dumper Activity on LSASS]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Password Dumper Activity on LSASS status: experimental \\\ndescription: Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN \\\nreferences: [\'https://twitter.com/jackcr/status/807385668833968128\'] \\\ntags: [\'attack.credential_access\', \'attack.t1003\'] \\\nauthor:  \\\ndate:  \\\nfalsepositives: [\'Unkown\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects process handle on LSASS process with certain access mask and object type SAM_DOMAIN\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="4656" ProcessName="C:\\\\Windows\\\\System32\\\\lsass.exe" AccessMask="0x705" ObjectType="SAM_DOMAIN") | stats values(*) AS * by _time | search NOT [| inputlookup Password_Dumper_Activity_on_LSASS_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.credential_access,sigma_tag=attack.t1003,level=high"\n\n\n'
```
