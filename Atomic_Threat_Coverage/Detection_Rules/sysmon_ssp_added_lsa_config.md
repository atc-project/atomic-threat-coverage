| Title                | Security Support Provider (SSP) added to LSA configuration                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows.                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1011: Exfiltration Over Other Network Medium](https://attack.mitre.org/techniques/T1011)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1011: Exfiltration Over Other Network Medium](../Triggers/T1011.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>Unlikely</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://attack.mitre.org/techniques/T1101/](https://attack.mitre.org/techniques/T1101/)</li><li>[https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/](https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/)</li></ul>                                                          |
| Author               | iwillkeepwatch                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Security Support Provider (SSP) added to LSA configuration
status: experimental
description: Detects the addition of a SSP to the registry. Upon a reboot or API call, SSP DLLs gain access to encrypted and plaintext passwords stored in Windows. 
references:
    - https://attack.mitre.org/techniques/T1101/
    - https://powersploit.readthedocs.io/en/latest/Persistence/Install-SSP/
tags:
    - attack.persistence
    - attack.t1011
author: iwillkeepwatch
date: 2019/01/18
logsource:
    product: windows
    service: sysmon
detection:
    selection_registry:
        EventID: 13
        TargetObject: 
            - 'HKLM\System\CurrentControlSet\Control\Lsa\Security Packages'
            - 'HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages'
    exclusion_images:
        - Image: C:\Windows\system32\msiexec.exe
        - Image: C:\Windows\syswow64\MsiExec.exe
    condition: selection_registry and not exclusion_images
falsepositives:
    - Unlikely
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
((EventID:"13" AND TargetObject:("HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\Security Packages" "HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\Lsa\\\\OSConfig\\\\Security Packages")) AND NOT (Image:"C\\:\\\\Windows\\\\system32\\\\msiexec.exe" OR Image:"C\\:\\\\Windows\\\\syswow64\\\\MsiExec.exe"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*13)(?=.*(?:.*HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Security Packages|.*HKLM\\System\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages))))(?=.*(?!.*(?:.*(?:.*(?=.*C:\\Windows\\system32\\msiexec\\.exe)|.*(?=.*C:\\Windows\\syswow64\\MsiExec\\.exe))))))'
```



