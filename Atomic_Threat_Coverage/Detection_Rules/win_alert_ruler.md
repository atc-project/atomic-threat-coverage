| Title                    | Hacktool Ruler       |
|:-------------------------|:------------------|
| **Description**          | This events that are generated when using the hacktool Ruler by Sensepost |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li><li>[T1114: Email Collection](https://attack.mitre.org/techniques/T1114)</li><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1550.002: Pass the Hash](https://attack.mitre.org/techniques/T1550.002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account](../Data_Needed/DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1550.002: Pass the Hash](../Triggers/T1550.002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Go utilities that use staaldraad awesome NTLM library</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://github.com/sensepost/ruler](https://github.com/sensepost/ruler)</li><li>[https://github.com/sensepost/ruler/issues/47](https://github.com/sensepost/ruler/issues/47)</li><li>[https://github.com/staaldraad/go-ntlm/blob/master/ntlm/ntlmv1.go#L427](https://github.com/staaldraad/go-ntlm/blob/master/ntlm/ntlmv1.go#L427)</li><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776)</li><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Hacktool Ruler
id: 24549159-ac1b-479c-8175-d42aea947cae
description: This events that are generated when using the hacktool Ruler by Sensepost
author: Florian Roth
date: 2017/05/31
modified: 2019/07/26
references:
    - https://github.com/sensepost/ruler
    - https://github.com/sensepost/ruler/issues/47
    - https://github.com/staaldraad/go-ntlm/blob/master/ntlm/ntlmv1.go#L427
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
tags:
    - attack.discovery
    - attack.execution
    - attack.t1087
    - attack.t1075          # an old one
    - attack.t1114
    - attack.t1059
    - attack.t1550.002
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
            - 4776
        Workstation: 'RULER'
    selection2:
        EventID:
            - 4624
            - 4625
        WorkstationName: 'RULER'
    condition: (1 of selection*)
falsepositives:
    - Go utilities that use staaldraad awesome NTLM library
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(((($_.ID -eq "4776") -and $_.message -match "Workstation.*RULER") -or (($_.ID -eq "4624" -or $_.ID -eq "4625") -and $_.message -match "WorkstationName.*RULER"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND ((winlog.event_id:("4776") AND Workstation:"RULER") OR (winlog.event_id:("4624" OR "4625") AND winlog.event_data.WorkstationName:"RULER")))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/24549159-ac1b-479c-8175-d42aea947cae <<EOF\n{\n  "metadata": {\n    "title": "Hacktool Ruler",\n    "description": "This events that are generated when using the hacktool Ruler by Sensepost",\n    "tags": [\n      "attack.discovery",\n      "attack.execution",\n      "attack.t1087",\n      "attack.t1075",\n      "attack.t1114",\n      "attack.t1059",\n      "attack.t1550.002"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND ((winlog.event_id:(\\"4776\\") AND Workstation:\\"RULER\\") OR (winlog.event_id:(\\"4624\\" OR \\"4625\\") AND winlog.event_data.WorkstationName:\\"RULER\\")))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND ((winlog.event_id:(\\"4776\\") AND Workstation:\\"RULER\\") OR (winlog.event_id:(\\"4624\\" OR \\"4625\\") AND winlog.event_data.WorkstationName:\\"RULER\\")))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Hacktool Ruler\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:("4776") AND Workstation:"RULER") OR (EventID:("4624" "4625") AND WorkstationName:"RULER"))
```


### splunk
    
```
(source="WinEventLog:Security" (((EventCode="4776") Workstation="RULER") OR ((EventCode="4624" OR EventCode="4625") WorkstationName="RULER")))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" ((event_id IN ["4776"] Workstation="RULER") OR (event_id IN ["4624", "4625"] WorkstationName="RULER")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*4776))(?=.*RULER))|.*(?:.*(?=.*(?:.*4624|.*4625))(?=.*RULER))))'
```



