| Title                    | Executable in ADS       |
|:-------------------------|:------------------|
| **Description**          | Detects the creation of an ADS data stream that contains an executable (non-empty imphash) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0019_15_windows_sysmon_FileCreateStreamHash](../Data_Needed/DN_0019_15_windows_sysmon_FileCreateStreamHash.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/0xrawsec/status/1002478725605273600?s=21](https://twitter.com/0xrawsec/status/1002478725605273600?s=21)</li></ul>  |
| **Author**               | Florian Roth, @0xrawsec |
| Other Tags           | <ul><li>attack.s0139</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Executable in ADS
id: b69888d4-380c-45ce-9cf9-d9ce46e67821
status: experimental
description: Detects the creation of an ADS data stream that contains an executable (non-empty imphash)
references:
    - https://twitter.com/0xrawsec/status/1002478725605273600?s=21
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.s0139
author: Florian Roth, @0xrawsec
date: 2018/06/03
logsource:
    product: windows
    service: sysmon
    definition: 'Requirements: Sysmon config with Imphash logging activated'
detection:
    selection:
        EventID: 15
    filter:
        Imphash: 
            - '00000000000000000000000000000000'
            - null
    condition: selection and not filter
fields:
    - TargetFilename
    - Image
falsepositives:
    - unknown
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

```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```

```



