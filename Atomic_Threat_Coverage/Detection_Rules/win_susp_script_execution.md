| Title                | WSF/JSE/JS/VBA/VBE File Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious file execution by wscript and cscript                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Will need to be tuned. I recommend adding the user profile path in CommandLine if it is getting too noisy.</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Michael Haag                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: WSF/JSE/JS/VBA/VBE File Execution
status: experimental
description: Detects suspicious file execution by wscript and cscript
author: Michael Haag
tags:
    - attack.execution
    - attack.t1064
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\wscript.exe'
            - '*\cscript.exe'
        CommandLine:
            - '*.jse'
            - '*.vbe'
            - '*.js'
            - '*.vba'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Will need to be tuned. I recommend adding the user profile path in CommandLine if it is getting too noisy.
level: medium

```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(Image:("*\\\\wscript.exe" "*\\\\cscript.exe") AND CommandLine:("*.jse" "*.vbe" "*.js" "*.vba"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\wscript\\.exe|.*.*\\cscript\\.exe))(?=.*(?:.*.*\\.jse|.*.*\\.vbe|.*.*\\.js|.*.*\\.vba)))'
```



