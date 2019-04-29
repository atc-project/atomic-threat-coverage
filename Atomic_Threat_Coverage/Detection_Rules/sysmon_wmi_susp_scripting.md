| Title                | Suspicious Scripting in a WMI Consumer                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious scripting in WMI Event Consumers                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0023_20_windows_sysmon_WmiEvent](../Data_Needed/DN_0023_20_windows_sysmon_WmiEvent.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Administrative scripts</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/](https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/)</li><li>[https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19](https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious Scripting in a WMI Consumer
status: experimental
description: Detects suspicious scripting in WMI Event Consumers 
author: Florian Roth
references:
    - https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
    - https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19
date: 2019/04/15
tags:
    - attack.t1086
    - attack.execution
logsource:
   product: windows
   service: sysmon
detection:
    selection:
        EventID: 20
        Destination:
            - '*new-object system.net.webclient).downloadstring(*'
            - '*new-object system.net.webclient).downloadfile(*'
            - '*new-object net.webclient).downloadstring(*'
            - '*new-object net.webclient).downloadfile(*'
            - '* iex(*'
            - '*WScript.shell*'
            - '* -nop *'
            - '* -noprofile *'
            - '* -decode *'
            - '* -enc *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
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
(EventID:"20" AND Destination:("*new\\-object system.net.webclient\\).downloadstring\\(*" "*new\\-object system.net.webclient\\).downloadfile\\(*" "*new\\-object net.webclient\\).downloadstring\\(*" "*new\\-object net.webclient\\).downloadfile\\(*" "* iex\\(*" "*WScript.shell*" "* \\-nop *" "* \\-noprofile *" "* \\-decode *" "* \\-enc *"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*20)(?=.*(?:.*.*new-object system\\.net\\.webclient\\)\\.downloadstring\\(.*|.*.*new-object system\\.net\\.webclient\\)\\.downloadfile\\(.*|.*.*new-object net\\.webclient\\)\\.downloadstring\\(.*|.*.*new-object net\\.webclient\\)\\.downloadfile\\(.*|.*.* iex\\(.*|.*.*WScript\\.shell.*|.*.* -nop .*|.*.* -noprofile .*|.*.* -decode .*|.*.* -enc .*)))'
```



