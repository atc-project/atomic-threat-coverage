| Title                | Antivirus Relevant File Paths Alerts                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects an Antivirus alert in a highly relevant file path or with a relevant file name                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0084_av_alert](../Data_Needed/DN_0084_av_alert.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/](https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Antivirus Relevant File Paths Alerts
description: Detects an Antivirus alert in a highly relevant file path or with a relevant file name
date: 2018/09/09
author: Florian Roth
references:
    - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/
logsource:
    product: antivirus
detection:
    selection:
        FileName:
            - 'C:\Windows\Temp\\*'
            - 'C:\Temp\\*'
            - '*\\Client\\*'
            - 'C:\PerfLogs\\*'
            - 'C:\Users\Public\\*'
            - 'C:\Users\Default\\*'
            - '*.ps1'
            - '*.vbs'
            - '*.bat'
            - '*.chm'
            - '*.xml'
            - '*.txt'
            - '*.jsp'
            - '*.jspx'
            - '*.asp'
            - '*.aspx'
            - '*.php'
            - '*.war'
    condition: selection
fields:
    - Signature
    - User
falsepositives:
    - Unlikely
level: high

```





### es-qs
    
```
FileName.keyword:(C\\:\\\\Windows\\\\Temp\\\\* C\\:\\\\Temp\\\\* *\\\\Client\\\\* C\\:\\\\PerfLogs\\\\* C\\:\\\\Users\\\\Public\\\\* C\\:\\\\Users\\\\Default\\\\* *.ps1 *.vbs *.bat *.chm *.xml *.txt *.jsp *.jspx *.asp *.aspx *.php *.war)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Antivirus-Relevant-File-Paths-Alerts <<EOF\n{\n  "metadata": {\n    "title": "Antivirus Relevant File Paths Alerts",\n    "description": "Detects an Antivirus alert in a highly relevant file path or with a relevant file name",\n    "tags": "",\n    "query": "FileName.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\* C\\\\:\\\\\\\\Temp\\\\\\\\* *\\\\\\\\Client\\\\\\\\* C\\\\:\\\\\\\\PerfLogs\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\\\\\* *.ps1 *.vbs *.bat *.chm *.xml *.txt *.jsp *.jspx *.asp *.aspx *.php *.war)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "FileName.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\* C\\\\:\\\\\\\\Temp\\\\\\\\* *\\\\\\\\Client\\\\\\\\* C\\\\:\\\\\\\\PerfLogs\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\\\\\* C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\\\\\* *.ps1 *.vbs *.bat *.chm *.xml *.txt *.jsp *.jspx *.asp *.aspx *.php *.war)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Antivirus Relevant File Paths Alerts\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nSignature = {{_source.Signature}}\\n     User = {{_source.User}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
FileName:("C\\:\\\\Windows\\\\Temp\\\\*" "C\\:\\\\Temp\\\\*" "*\\\\Client\\\\*" "C\\:\\\\PerfLogs\\\\*" "C\\:\\\\Users\\\\Public\\\\*" "C\\:\\\\Users\\\\Default\\\\*" "*.ps1" "*.vbs" "*.bat" "*.chm" "*.xml" "*.txt" "*.jsp" "*.jspx" "*.asp" "*.aspx" "*.php" "*.war")
```


### splunk
    
```
(FileName="C:\\\\Windows\\\\Temp\\\\*" OR FileName="C:\\\\Temp\\\\*" OR FileName="*\\\\Client\\\\*" OR FileName="C:\\\\PerfLogs\\\\*" OR FileName="C:\\\\Users\\\\Public\\\\*" OR FileName="C:\\\\Users\\\\Default\\\\*" OR FileName="*.ps1" OR FileName="*.vbs" OR FileName="*.bat" OR FileName="*.chm" OR FileName="*.xml" OR FileName="*.txt" OR FileName="*.jsp" OR FileName="*.jspx" OR FileName="*.asp" OR FileName="*.aspx" OR FileName="*.php" OR FileName="*.war") | table Signature,User
```


### logpoint
    
```
FileName IN ["C:\\\\Windows\\\\Temp\\\\*", "C:\\\\Temp\\\\*", "*\\\\Client\\\\*", "C:\\\\PerfLogs\\\\*", "C:\\\\Users\\\\Public\\\\*", "C:\\\\Users\\\\Default\\\\*", "*.ps1", "*.vbs", "*.bat", "*.chm", "*.xml", "*.txt", "*.jsp", "*.jspx", "*.asp", "*.aspx", "*.php", "*.war"]
```


### grep
    
```
grep -P '^(?:.*C:\\Windows\\Temp\\\\.*|.*C:\\Temp\\\\.*|.*.*\\\\Client\\\\.*|.*C:\\PerfLogs\\\\.*|.*C:\\Users\\Public\\\\.*|.*C:\\Users\\Default\\\\.*|.*.*\\.ps1|.*.*\\.vbs|.*.*\\.bat|.*.*\\.chm|.*.*\\.xml|.*.*\\.txt|.*.*\\.jsp|.*.*\\.jspx|.*.*\\.asp|.*.*\\.aspx|.*.*\\.php|.*.*\\.war)'
```



