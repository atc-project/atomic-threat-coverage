| Title                | Suspicious Kerberos RC4 Ticket Encryption                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects service ticket requests using RC4 encryption type                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0077_4769_kerberos_service_ticket_was_requested](../Data_Needed/DN_0077_4769_kerberos_service_ticket_was_requested.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1208: Kerberoasting](../Triggers/T1208.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Service accounts used on legacy systems (e.g. NetApp)</li><li>Windows Domains with DFL 2003 and legacy systems</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://adsecurity.org/?p=3458](https://adsecurity.org/?p=3458)</li><li>[https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity](https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity)</li></ul>                                                          |
| Author               |                                                                                                                                                 |


## Detection Rules

### Sigma rule

```
title: Suspicious Kerberos RC4 Ticket Encryption
status: experimental
references:
    - https://adsecurity.org/?p=3458
    - https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity
tags:
    - attack.credential_access
    - attack.t1208
description: Detects service ticket requests using RC4 encryption type
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketOptions: '0x40810000'
        TicketEncryptionType: '0x17'
    reduction:
        - ServiceName: '$*'
    condition: selection and not reduction
falsepositives:
    - Service accounts used on legacy systems (e.g. NetApp)
    - Windows Domains with DFL 2003 and legacy systems
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
((EventID:"4769" AND TicketOptions:"0x40810000" AND TicketEncryptionType:"0x17") AND NOT (ServiceName:"$*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4769)(?=.*0x40810000)(?=.*0x17)))(?=.*(?!.*(?:.*(?:.*(?=.*\\$.*))))))'
```



