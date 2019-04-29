| Title                | First time seen remote named pipe                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>update the excluded named pipe to filter out any newly observed legit named pipe</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul><li>[https://twitter.com/menasec1/status/1104489274387451904](https://twitter.com/menasec1/status/1104489274387451904)</li></ul>                                                          |
| Author               | Samir Bousseaden                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: First time seen remote named pipe
description: This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes
author: Samir Bousseaden
references:
    - https://twitter.com/menasec1/status/1104489274387451904
tags:
    - attack.lateral_movement
    - attack.t1077
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection1:
        EventID: 5145
        ShareName: \\*\IPC$
    selection2:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName:
         - 'atsvc'
         - 'samr'
         - 'lsarpc'
         - 'winreg'
         - 'netlogon'
         - 'srvsvc'
         - 'protected_storage'
         - 'wkssvc'
         - 'browser'
         - 'netdfs'
    condition: selection1 and not selection2
falsepositives: 
    - update the excluded named pipe to filter out any newly observed legit named pipe
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
((EventID:"5145" AND ShareName:"\\\\*\\\\IPC$") AND NOT (EventID:"5145" AND ShareName:"\\\\*\\\\IPC$" AND RelativeTargetName:("atsvc" "samr" "lsarpc" "winreg" "netlogon" "srvsvc" "protected_storage" "wkssvc" "browser" "netdfs")))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*5145)(?=.*\\\\.*\\IPC\\$)))(?=.*(?!.*(?:.*(?=.*5145)(?=.*\\\\.*\\IPC\\$)(?=.*(?:.*atsvc|.*samr|.*lsarpc|.*winreg|.*netlogon|.*srvsvc|.*protected_storage|.*wkssvc|.*browser|.*netdfs))))))'
```



