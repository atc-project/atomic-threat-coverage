| Title                | Possible Applocker Bypass                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of executables that can be used to bypass Applocker whitelisting                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1118: InstallUtil](https://attack.mitre.org/techniques/T1118)</li><li>[T1121: Regsvcs/Regasm](https://attack.mitre.org/techniques/T1121)</li><li>[T1127: Trusted Developer Utilities](https://attack.mitre.org/techniques/T1127)</li><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1118: InstallUtil](../Triggers/T1118.md)</li><li>[T1121: Regsvcs/Regasm](../Triggers/T1121.md)</li><li>[T1127: Trusted Developer Utilities](../Triggers/T1127.md)</li><li>[T1170: Mshta](../Triggers/T1170.md)</li></ul>  |
| Severity Level       | low                                                                                                                                                 |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li><li>Using installutil to add features for .NET applications (primarly would occur in developer environments)</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt](https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt)</li><li>[https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/](https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/)</li></ul>                                                          |
| Author               | juju4                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Possible Applocker Bypass
description: Detects execution of executables that can be used to bypass Applocker whitelisting
status: experimental
references:
    - https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt
    - https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/
author: juju4
tags:
    - attack.defense_evasion
    - attack.t1118
    - attack.t1121
    - attack.t1127
    - attack.t1170
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\msdt.exe*'
            - '*\installutil.exe*'
            - '*\regsvcs.exe*'
            - '*\regasm.exe*'
            - '*\regsvr32.exe*'
            - '*\msbuild.exe*'
            - '*\ieexec.exe*'
            - '*\mshta.exe*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
    - Using installutil to add features for .NET applications (primarly would occur in developer environments)
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
CommandLine:("*\\\\msdt.exe*" "*\\\\installutil.exe*" "*\\\\regsvcs.exe*" "*\\\\regasm.exe*" "*\\\\regsvr32.exe*" "*\\\\msbuild.exe*" "*\\\\ieexec.exe*" "*\\\\mshta.exe*")
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*.*\\msdt\\.exe.*|.*.*\\installutil\\.exe.*|.*.*\\regsvcs\\.exe.*|.*.*\\regasm\\.exe.*|.*.*\\regsvr32\\.exe.*|.*.*\\msbuild\\.exe.*|.*.*\\ieexec\\.exe.*|.*.*\\mshta\\.exe.*)'
```



