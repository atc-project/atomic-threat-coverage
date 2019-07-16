| Title                | Hacktool Use                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This method detects well-known keywords, certain field combination that appear in Windows Eventlog when certain hack tools are used                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li><li>[T1114: Email Collection](https://attack.mitre.org/techniques/T1114)</li><li>[T1059: Command-Line Interface](https://attack.mitre.org/techniques/T1059)</li></ul>  |
| Data Needed          | <ul><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li><li>[DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account](../Data_Needed/DN_0079_4776_computer_attempted_to_validate_the_credentials_for_an_account.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li><li>[T1114: Email Collection](../Triggers/T1114.md)</li><li>[T1059: Command-Line Interface](../Triggers/T1059.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Hacktool Use
description: This method detects well-known keywords, certain field combination that appear in Windows Eventlog when certain hack tools are used
author: Florian Roth
tags:
    - attack.discovery
    - attack.execution
    - attack.t1087
    - attack.t1075
    - attack.t1114
    - attack.t1059
logsource:
    product: windows
    service: security
detection:
    # Ruler https://github.com/sensepost/ruler
    selection1:
        EventID: 
          - 4776
          - 4624
          - 4625
        WorkstationName: 'RULER'
    condition: selection1
falsepositives:
    - Unlikely
level: critical

```





### es-qs
    
```
(EventID:("4776" "4624" "4625") AND WorkstationName:"RULER")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Hacktool-Use <<EOF\n{\n  "metadata": {\n    "title": "Hacktool Use",\n    "description": "This method detects well-known keywords, certain field combination that appear in Windows Eventlog when certain hack tools are used",\n    "tags": [\n      "attack.discovery",\n      "attack.execution",\n      "attack.t1087",\n      "attack.t1075",\n      "attack.t1114",\n      "attack.t1059"\n    ],\n    "query": "(EventID:(\\"4776\\" \\"4624\\" \\"4625\\") AND WorkstationName:\\"RULER\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"4776\\" \\"4624\\" \\"4625\\") AND WorkstationName:\\"RULER\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Hacktool Use\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("4776" "4624" "4625") AND WorkstationName:"RULER")
```


### splunk
    
```
((EventID="4776" OR EventID="4624" OR EventID="4625") WorkstationName="RULER")
```


### logpoint
    
```
(EventID IN ["4776", "4624", "4625"] WorkstationName="RULER")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4776|.*4624|.*4625))(?=.*RULER))'
```



