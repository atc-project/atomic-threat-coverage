| Title                | Suspicious access to sensitive file extensions                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects known sensitive file extensions                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Help Desk operator doing backup or re-imaging end user machine or pentest or backup software</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Samir Bousseaden                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious access to sensitive file extensions
description: Detects known sensitive file extensions
author: Samir Bousseaden
tags:
    - attack.collection
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 5145
        RelativeTargetName:
            - '*.pst'
            - '*.ost'
            - '*.msg'
            - '*.nst'
            - '*.oab'
            - '*.edb'
            - '*.nsf' 
            - '*.bak'
            - '*.dmp'
            - '*.kirbi'
            - '*\ntds.dit'
            - '*\groups.xml'
            - '*.rdp'
    condition: selection
falsepositives:
    - Help Desk operator doing backup or re-imaging end user machine or pentest or backup software
level: high

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(EventID:("5145") AND RelativeTargetName:("*.pst" "*.ost" "*.msg" "*.nst" "*.oab" "*.edb" "*.nsf" "*.bak" "*.dmp" "*.kirbi" "*\\\\ntds.dit" "*\\\\groups.xml" "*.rdp"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*5145))(?=.*(?:.*.*\\.pst|.*.*\\.ost|.*.*\\.msg|.*.*\\.nst|.*.*\\.oab|.*.*\\.edb|.*.*\\.nsf|.*.*\\.bak|.*.*\\.dmp|.*.*\\.kirbi|.*.*\\ntds\\.dit|.*.*\\groups\\.xml|.*.*\\.rdp)))'
```



