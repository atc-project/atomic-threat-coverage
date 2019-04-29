| Title                | WCE wceaux.dll Access                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0061_4660_object_was_deleted](../Data_Needed/DN_0061_4660_object_was_deleted.md)</li><li>[DN_0060_4658_handle_to_an_object_was_closed](../Data_Needed/DN_0060_4658_handle_to_an_object_was_closed.md)</li><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li><li>[DN_0062_4663_attempt_was_made_to_access_an_object](../Data_Needed/DN_0062_4663_attempt_was_made_to_access_an_object.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Penetration testing</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www.jpcert.or.jp/english/pub/sr/ir_research.html](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)</li><li>[https://jpcertcc.github.io/ToolAnalysisResultSheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)</li></ul>                                                          |
| Author               | Thomas Patzke                                                                                                                                                |
| Other Tags           | <ul><li>attack.s0005</li><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: WCE wceaux.dll Access
status: experimental
description: Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host
author: Thomas Patzke
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4658
            - 4660
            - 4663
        ObjectName: '*\wceaux.dll'
    condition: selection
falsepositives: 
    - Penetration testing
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
(EventID:("4656" "4658" "4660" "4663") AND ObjectName:"*\\\\wceaux.dll")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4656|.*4658|.*4660|.*4663))(?=.*.*\\wceaux\\.dll))'
```



