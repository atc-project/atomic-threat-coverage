| Title                | DNS Server Error Failed Loading the ServerLevelPluginDLL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| Data Needed          | <ul><li>[DN_0036_150_dns_server_could_not_load_dll](../Data_Needed/DN_0036_150_dns_server_could_not_load_dll.md)</li><li>[DN_0043_770_dns_server_plugin_dll_has_been_loaded](../Data_Needed/DN_0043_770_dns_server_plugin_dll_has_been_loaded.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)</li><li>[https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx)</li><li>[https://twitter.com/gentilkiwi/status/861641945944391680](https://twitter.com/gentilkiwi/status/861641945944391680)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: DNS Server Error Failed Loading the ServerLevelPluginDLL
id: cbe51394-cd93-4473-b555-edf0144952d9
description: This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded
status: experimental
date: 2017/05/08
references:
    - https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83
    - https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx
    - https://twitter.com/gentilkiwi/status/861641945944391680
tags:
    - attack.defense_evasion
    - attack.t1073
author: Florian Roth
logsource:
    product: windows
    service: dns-server
detection:
    selection:
        EventID: 
            - 150
            - 770
    condition: selection
falsepositives: 
    - Unknown
level: critical



```





### splunk
    
```
(EventID="150" OR EventID="770")
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[DNS Server Error Failed Loading the ServerLevelPluginDLL]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: DNS Server Error Failed Loading the ServerLevelPluginDLL status: experimental \\\ndescription: This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded \\\nreferences: [\'https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83\', \'https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx\', \'https://twitter.com/gentilkiwi/status/861641945944391680\'] \\\ntags: [\'attack.defense_evasion\', \'attack.t1073\'] \\\nauthor: Florian Roth \\\ndate:  \\\nfalsepositives: [\'Unknown\'] \\\nlevel: critical\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="150" OR EventID="770") | stats values(*) AS * by _time | search NOT [| inputlookup DNS_Server_Error_Failed_Loading_the_ServerLevelPluginDLL_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1073,level=critical"\n\n\n'
```
