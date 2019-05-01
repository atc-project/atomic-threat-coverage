| Title                | DNS Server Error Failed Loading the ServerLevelPluginDLL                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This rule detects a DNS server error in which a specified plugin DLL (in registry) could not be loaded                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0036_150_dns_server_could_not_load_dll](../Data_Needed/DN_0036_150_dns_server_could_not_load_dll.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83)</li><li>[https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx](https://technet.microsoft.com/en-us/library/cc735829(v=ws.10).aspx)</li><li>[https://twitter.com/gentilkiwi/status/861641945944391680](https://twitter.com/gentilkiwi/status/861641945944391680)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: DNS Server Error Failed Loading the ServerLevelPluginDLL
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





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
EventID:("150" "770")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*150|.*770)'
```



