| Title                | PowerShell Network Connections                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Powershell process that opens network connections - check for suspicious target ports and target systems - adjust to your environment (e.g. extend filters with company's ip range')                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>Administrative scripts</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.youtube.com/watch?v=DLtJTxMWZ2o](https://www.youtube.com/watch?v=DLtJTxMWZ2o)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: PowerShell Network Connections
status: experimental
description: "Detects a Powershell process that opens network connections - check for suspicious target ports and target systems - adjust to your environment (e.g. extend filters with company's ip range')"  
author: Florian Roth
references:
    - https://www.youtube.com/watch?v=DLtJTxMWZ2o
tags:
    - attack.execution
    - attack.t1086
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        Image: '*\powershell.exe'
    filter:
        DestinationIp: 
            - '10.*'
            - '192.168.*'
            - '172.16.*'
            - '172.17.*'
            - '172.18.*'
            - '172.19.*'
            - '172.20.*'
            - '172.21.*'
            - '172.22.*'
            - '172.23.*'
            - '172.24.*'
            - '172.25.*'
            - '172.26.*'
            - '172.27.*'
            - '172.28.*'
            - '172.29.*'
            - '172.30.*'
            - '172.31.*'
            - '127.0.0.1'
        DestinationIsIpv6: 'false'
        User: 'NT AUTHORITY\SYSTEM'
    condition: selection and not filter
falsepositives:
    - Administrative scripts
level: low

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
((EventID:"3" AND Image:"*\\\\powershell.exe") AND NOT (DestinationIp:("10.*" "192.168.*" "172.16.*" "172.17.*" "172.18.*" "172.19.*" "172.20.*" "172.21.*" "172.22.*" "172.23.*" "172.24.*" "172.25.*" "172.26.*" "172.27.*" "172.28.*" "172.29.*" "172.30.*" "172.31.*" "127.0.0.1") AND DestinationIsIpv6:"false" AND User:"NT AUTHORITY\\\\SYSTEM"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*3)(?=.*.*\\powershell\\.exe)))(?=.*(?!.*(?:.*(?=.*(?:.*10\\..*|.*192\\.168\\..*|.*172\\.16\\..*|.*172\\.17\\..*|.*172\\.18\\..*|.*172\\.19\\..*|.*172\\.20\\..*|.*172\\.21\\..*|.*172\\.22\\..*|.*172\\.23\\..*|.*172\\.24\\..*|.*172\\.25\\..*|.*172\\.26\\..*|.*172\\.27\\..*|.*172\\.28\\..*|.*172\\.29\\..*|.*172\\.30\\..*|.*172\\.31\\..*|.*127\\.0\\.0\\.1))(?=.*false)(?=.*NT AUTHORITY\\SYSTEM)))))'
```



