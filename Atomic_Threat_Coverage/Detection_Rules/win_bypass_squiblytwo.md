| Title                | SquiblyTwo                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects WMI SquiblyTwo Attack with possible renamed WMI by looking for imphash                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://subt0x11.blogspot.ch/2018/04/wmicexe-whitelisting-bypass-hacking.html](https://subt0x11.blogspot.ch/2018/04/wmicexe-whitelisting-bypass-hacking.html)</li><li>[https://twitter.com/mattifestation/status/986280382042595328](https://twitter.com/mattifestation/status/986280382042595328)</li></ul>                                                          |
| Author               | Markus Neis / Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: SquiblyTwo
status: experimental
description: Detects WMI SquiblyTwo Attack with possible renamed WMI by looking for imphash
references:
    - https://subt0x11.blogspot.ch/2018/04/wmicexe-whitelisting-bypass-hacking.html
    - https://twitter.com/mattifestation/status/986280382042595328
tags:
    - attack.defense_evasion
    - attack.t1047
author: Markus Neis / Florian Roth
falsepositives:
    - Unknown
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image:
            - '*\wmic.exe'
        CommandLine:
            - wmic * *format:\"http*
            - wmic * /format:'http
            - wmic * /format:http*
    selection2:
        Imphash:
            - 1B1A3F43BF37B5BFE60751F2EE2F326E
            - 37777A96245A3C74EB217308F3546F4C
            - 9D87C9D67CE724033C0B40CC4CA1B206
        CommandLine:
            - '* *format:\"http*'
            - '* /format:''http'
            - '* /format:http*'
    condition: 1 of them

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
((Image:("*\\\\wmic.exe") AND CommandLine:("wmic * *format\\:\\\\\\"http*" "wmic * \\/format\\:\'http" "wmic * \\/format\\:http*")) OR (Imphash:("1B1A3F43BF37B5BFE60751F2EE2F326E" "37777A96245A3C74EB217308F3546F4C" "9D87C9D67CE724033C0B40CC4CA1B206") AND CommandLine:("* *format\\:\\\\\\"http*" "* \\/format\\:\'http" "* \\/format\\:http*")))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P \'^(?:.*(?:.*(?:.*(?=.*(?:.*.*\\wmic\\.exe))(?=.*(?:.*wmic .* .*format:\\"http.*|.*wmic .* /format:\'"\'"\'http|.*wmic .* /format:http.*)))|.*(?:.*(?=.*(?:.*1B1A3F43BF37B5BFE60751F2EE2F326E|.*37777A96245A3C74EB217308F3546F4C|.*9D87C9D67CE724033C0B40CC4CA1B206))(?=.*(?:.*.* .*format:\\"http.*|.*.* /format:\'"\'"\'http|.*.* /format:http.*)))))\'
```



