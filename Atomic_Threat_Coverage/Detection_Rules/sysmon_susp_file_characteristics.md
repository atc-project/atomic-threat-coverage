| Title                | Suspicious File Characteristics due to Missing Fields                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Executables without FileVersion,Description,Product,Company likely created with py2exe                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>                             |
| Data Needed          | <ul></ul>                                                         |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://securelist.com/muddywater/88059/](https://securelist.com/muddywater/88059/)</li><li>[https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection](https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious File Characteristics due to Missing Fields
description: Detects Executables without FileVersion,Description,Product,Company likely created with py2exe
status: experimental
references:
    - https://securelist.com/muddywater/88059/
    - https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection
author: Markus Neis
date: 2018/11/22
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1064
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        Description: '\?'
        FileVersion: '\?'
    selection2:
        Description: '\?'
        Product: '\?'
    selection3:
        Description: '\?'
        Company: '\?' 
    condition: 1 of them
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
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
(Description:"\\?" AND (FileVersion:"\\?" OR Product:"\\?" OR Company:"\\?"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*\\?)(?=.*(?:.*(?:.*\\?|.*\\?|.*\\?))))'
```



