| Title                | Kerberos Manipulation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1212: Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0076_4768_kerberos_authentication_ticket_was_requested](../Data_Needed/DN_0076_4768_kerberos_authentication_ticket_was_requested.md)</li><li>[DN_0077_4769_kerberos_service_ticket_was_requested](../Data_Needed/DN_0077_4769_kerberos_service_ticket_was_requested.md)</li><li>[DN_0078_4771_kerberos_pre_authentication_failed](../Data_Needed/DN_0078_4771_kerberos_pre_authentication_failed.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1212: Exploitation for Credential Access](../Triggers/T1212.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Faulty legacy applications</li></ul>                                                                  |
| Development Status   |                                                                                                                                                 |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Kerberos Manipulation
description: This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages
author: Florian Roth
tags:
    - attack.credential_access
    - attack.t1212
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
          - 675
          - 4768
          - 4769
          - 4771
        FailureCode:
          - '0x9'
          - '0xA'
          - '0xB'
          - '0xF'
          - '0x10'
          - '0x11'
          - '0x13'
          - '0x14'
          - '0x1A'
          - '0x1F'
          - '0x21'
          - '0x22'
          - '0x23'
          - '0x24'
          - '0x26'
          - '0x27'
          - '0x28'
          - '0x29'
          - '0x2C'
          - '0x2D'
          - '0x2E'
          - '0x2F'
          - '0x31'
          - '0x32'
          - '0x3E'
          - '0x3F'
          - '0x40'
          - '0x41'
          - '0x43'
          - '0x44'
    condition: selection
falsepositives:
    - Faulty legacy applications
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
(EventID:("675" "4768" "4769" "4771") AND FailureCode:("0x9" "0xA" "0xB" "0xF" "0x10" "0x11" "0x13" "0x14" "0x1A" "0x1F" "0x21" "0x22" "0x23" "0x24" "0x26" "0x27" "0x28" "0x29" "0x2C" "0x2D" "0x2E" "0x2F" "0x31" "0x32" "0x3E" "0x3F" "0x40" "0x41" "0x43" "0x44"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*675|.*4768|.*4769|.*4771))(?=.*(?:.*0x9|.*0xA|.*0xB|.*0xF|.*0x10|.*0x11|.*0x13|.*0x14|.*0x1A|.*0x1F|.*0x21|.*0x22|.*0x23|.*0x24|.*0x26|.*0x27|.*0x28|.*0x29|.*0x2C|.*0x2D|.*0x2E|.*0x2F|.*0x31|.*0x32|.*0x3E|.*0x3F|.*0x40|.*0x41|.*0x43|.*0x44)))'
```



