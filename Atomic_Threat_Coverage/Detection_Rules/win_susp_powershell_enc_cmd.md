| Title                | Suspicious Encoded PowerShell Command Line                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious powershell process starts with base64 encoded commands                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e](https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e)</li></ul>                                                          |
| Author               | Florian Roth, Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious Encoded PowerShell Command Line
description: Detects suspicious powershell process starts with base64 encoded commands
status: experimental
references:
    - https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e
author: Florian Roth, Markus Neis
date: 2018/09/03
modified: 2019/04/20
tags:
  - attack.execution
  - attack.t1086
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -e JAB*'
            - '* -enc JAB*'
            - '* -encodedcommand JAB*'
            - '* BA^J e-'
            - '* -e SUVYI*'
            - '* -e aWV4I*'
            - '* -e SQBFAFgA*'
            - '* -e aQBlAHgA*'
            - '* -enc SUVYI*'
            - '* -enc aWV4I*'
            - '* -enc SQBFAFgA*'
            - '* -enc aQBlAHgA*'
    falsepositive1:
        CommandLine: '* -ExecutionPolicy remotesigned *'
    condition: selection and not falsepositive1
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
(CommandLine:("* \\-e JAB*" "* \\-enc JAB*" "* \\-encodedcommand JAB*" "* BA\\^J e\\-" "* \\-e SUVYI*" "* \\-e aWV4I*" "* \\-e SQBFAFgA*" "* \\-e aQBlAHgA*" "* \\-enc SUVYI*" "* \\-enc aWV4I*" "* \\-enc SQBFAFgA*" "* \\-enc aQBlAHgA*") AND NOT (CommandLine:"* \\-ExecutionPolicy remotesigned *"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.* -e JAB.*|.*.* -enc JAB.*|.*.* -encodedcommand JAB.*|.*.* BA\\^J e-|.*.* -e SUVYI.*|.*.* -e aWV4I.*|.*.* -e SQBFAFgA.*|.*.* -e aQBlAHgA.*|.*.* -enc SUVYI.*|.*.* -enc aWV4I.*|.*.* -enc SQBFAFgA.*|.*.* -enc aQBlAHgA.*))(?=.*(?!.*(?:.*(?=.*.* -ExecutionPolicy remotesigned .*)))))'
```



