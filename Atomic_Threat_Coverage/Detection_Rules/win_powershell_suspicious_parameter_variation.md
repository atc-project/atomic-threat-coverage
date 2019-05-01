| Title                | Suspicious PowerShell Parameter Substring                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell invocation with a parameter substring                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Penetration tests</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier](http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier)</li></ul>                                                          |
| Author               | Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix)                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Parameter Substring
status: experimental
description: Detects suspicious PowerShell invocation with a parameter substring
references:
    - http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier
tags:
    - attack.execution
    - attack.t1086
author: Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix)
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\Powershell.exe'
        CommandLine:
            - ' -windowstyle h '
            - ' -windowstyl h'
            - ' -windowsty h'
            - ' -windowst h'
            - ' -windows h'
            - ' -windo h'
            - ' -wind h'
            - ' -win h'
            - ' -wi h'
            - ' -win h '
            - ' -win hi '
            - ' -win hid '
            - ' -win hidd '
            - ' -win hidde '
            - ' -NoPr '
            - ' -NoPro '
            - ' -NoProf '
            - ' -NoProfi '
            - ' -NoProfil '
            - ' -nonin '
            - ' -nonint '
            - ' -noninte '
            - ' -noninter '
            - ' -nonintera '
            - ' -noninterac '
            - ' -noninteract '
            - ' -noninteracti '
            - ' -noninteractiv '
            - ' -ec '
            - ' -encodedComman '
            - ' -encodedComma '
            - ' -encodedComm '
            - ' -encodedCom '
            - ' -encodedCo '
            - ' -encodedC '
            - ' -encoded '
            - ' -encode '
            - ' -encod '
            - ' -enco '
            - ' -en '
    condition: selection
falsepositives:
    - Penetration tests
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
(Image:("*\\\\Powershell.exe") AND CommandLine:(" \\-windowstyle h " " \\-windowstyl h" " \\-windowsty h" " \\-windowst h" " \\-windows h" " \\-windo h" " \\-wind h" " \\-win h" " \\-wi h" " \\-win h " " \\-win hi " " \\-win hid " " \\-win hidd " " \\-win hidde " " \\-NoPr " " \\-NoPro " " \\-NoProf " " \\-NoProfi " " \\-NoProfil " " \\-nonin " " \\-nonint " " \\-noninte " " \\-noninter " " \\-nonintera " " \\-noninterac " " \\-noninteract " " \\-noninteracti " " \\-noninteractiv " " \\-ec " " \\-encodedComman " " \\-encodedComma " " \\-encodedComm " " \\-encodedCom " " \\-encodedCo " " \\-encodedC " " \\-encoded " " \\-encode " " \\-encod " " \\-enco " " \\-en "))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\Powershell\\.exe))(?=.*(?:.* -windowstyle h |.* -windowstyl h|.* -windowsty h|.* -windowst h|.* -windows h|.* -windo h|.* -wind h|.* -win h|.* -wi h|.* -win h |.* -win hi |.* -win hid |.* -win hidd |.* -win hidde |.* -NoPr |.* -NoPro |.* -NoProf |.* -NoProfi |.* -NoProfil |.* -nonin |.* -nonint |.* -noninte |.* -noninter |.* -nonintera |.* -noninterac |.* -noninteract |.* -noninteracti |.* -noninteractiv |.* -ec |.* -encodedComman |.* -encodedComma |.* -encodedComm |.* -encodedCom |.* -encodedCo |.* -encodedC |.* -encoded |.* -encode |.* -encod |.* -enco |.* -en )))'
```



