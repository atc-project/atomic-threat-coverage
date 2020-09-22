| Title                    | Antivirus Relevant File Paths Alerts       |
|:-------------------------|:------------------|
| **Description**          | Detects an Antivirus alert in a highly relevant file path or with a relevant file name |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          | <ul><li>[DN_0084_av_alert](../Data_Needed/DN_0084_av_alert.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/](https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Antivirus Relevant File Paths Alerts
id: c9a88268-0047-4824-ba6e-4d81ce0b907c
description: Detects an Antivirus alert in a highly relevant file path or with a relevant file name
date: 2018/09/09
modified: 2019/10/04
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
            - '*.hta'
            - '*.lnk'
            - '*.scf'
            - '*.sct'
            - '*.vbe'
            - '*.wsf'
            - '*.wsh'
    condition: selection
fields:
    - Signature
    - User
falsepositives:
    - Unlikely
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "FileName.*C:\\\\Windows\\\\Temp\\\\.*" -or $_.message -match "FileName.*C:\\\\Temp\\\\.*" -or $_.message -match "FileName.*.*\\\\Client\\\\.*" -or $_.message -match "FileName.*C:\\\\PerfLogs\\\\.*" -or $_.message -match "FileName.*C:\\\\Users\\\\Public\\\\.*" -or $_.message -match "FileName.*C:\\\\Users\\\\Default\\\\.*" -or $_.message -match "FileName.*.*.ps1" -or $_.message -match "FileName.*.*.vbs" -or $_.message -match "FileName.*.*.bat" -or $_.message -match "FileName.*.*.chm" -or $_.message -match "FileName.*.*.xml" -or $_.message -match "FileName.*.*.txt" -or $_.message -match "FileName.*.*.jsp" -or $_.message -match "FileName.*.*.jspx" -or $_.message -match "FileName.*.*.asp" -or $_.message -match "FileName.*.*.aspx" -or $_.message -match "FileName.*.*.php" -or $_.message -match "FileName.*.*.war" -or $_.message -match "FileName.*.*.hta" -or $_.message -match "FileName.*.*.lnk" -or $_.message -match "FileName.*.*.scf" -or $_.message -match "FileName.*.*.sct" -or $_.message -match "FileName.*.*.vbe" -or $_.message -match "FileName.*.*.wsf" -or $_.message -match "FileName.*.*.wsh") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.FileName.keyword:(C\\:\\\\Windows\\\\Temp\\\\* OR C\\:\\\\Temp\\\\* OR *\\\\Client\\\\* OR C\\:\\\\PerfLogs\\\\* OR C\\:\\\\Users\\\\Public\\\\* OR C\\:\\\\Users\\\\Default\\\\* OR *.ps1 OR *.vbs OR *.bat OR *.chm OR *.xml OR *.txt OR *.jsp OR *.jspx OR *.asp OR *.aspx OR *.php OR *.war OR *.hta OR *.lnk OR *.scf OR *.sct OR *.vbe OR *.wsf OR *.wsh)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/c9a88268-0047-4824-ba6e-4d81ce0b907c <<EOF\n{\n  "metadata": {\n    "title": "Antivirus Relevant File Paths Alerts",\n    "description": "Detects an Antivirus alert in a highly relevant file path or with a relevant file name",\n    "tags": "",\n    "query": "winlog.event_data.FileName.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\* OR C\\\\:\\\\\\\\Temp\\\\\\\\* OR *\\\\\\\\Client\\\\\\\\* OR C\\\\:\\\\\\\\PerfLogs\\\\\\\\* OR C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\\\\\* OR C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\\\\\* OR *.ps1 OR *.vbs OR *.bat OR *.chm OR *.xml OR *.txt OR *.jsp OR *.jspx OR *.asp OR *.aspx OR *.php OR *.war OR *.hta OR *.lnk OR *.scf OR *.sct OR *.vbe OR *.wsf OR *.wsh)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.FileName.keyword:(C\\\\:\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\* OR C\\\\:\\\\\\\\Temp\\\\\\\\* OR *\\\\\\\\Client\\\\\\\\* OR C\\\\:\\\\\\\\PerfLogs\\\\\\\\* OR C\\\\:\\\\\\\\Users\\\\\\\\Public\\\\\\\\* OR C\\\\:\\\\\\\\Users\\\\\\\\Default\\\\\\\\* OR *.ps1 OR *.vbs OR *.bat OR *.chm OR *.xml OR *.txt OR *.jsp OR *.jspx OR *.asp OR *.aspx OR *.php OR *.war OR *.hta OR *.lnk OR *.scf OR *.sct OR *.vbe OR *.wsf OR *.wsh)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Antivirus Relevant File Paths Alerts\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nSignature = {{_source.Signature}}\\n     User = {{_source.User}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
FileName.keyword:(C\\:\\\\Windows\\\\Temp\\\\* C\\:\\\\Temp\\\\* *\\\\Client\\\\* C\\:\\\\PerfLogs\\\\* C\\:\\\\Users\\\\Public\\\\* C\\:\\\\Users\\\\Default\\\\* *.ps1 *.vbs *.bat *.chm *.xml *.txt *.jsp *.jspx *.asp *.aspx *.php *.war *.hta *.lnk *.scf *.sct *.vbe *.wsf *.wsh)
```


### splunk
    
```
(FileName="C:\\\\Windows\\\\Temp\\\\*" OR FileName="C:\\\\Temp\\\\*" OR FileName="*\\\\Client\\\\*" OR FileName="C:\\\\PerfLogs\\\\*" OR FileName="C:\\\\Users\\\\Public\\\\*" OR FileName="C:\\\\Users\\\\Default\\\\*" OR FileName="*.ps1" OR FileName="*.vbs" OR FileName="*.bat" OR FileName="*.chm" OR FileName="*.xml" OR FileName="*.txt" OR FileName="*.jsp" OR FileName="*.jspx" OR FileName="*.asp" OR FileName="*.aspx" OR FileName="*.php" OR FileName="*.war" OR FileName="*.hta" OR FileName="*.lnk" OR FileName="*.scf" OR FileName="*.sct" OR FileName="*.vbe" OR FileName="*.wsf" OR FileName="*.wsh") | table Signature,User
```


### logpoint
    
```
FileName IN ["C:\\\\Windows\\\\Temp\\\\*", "C:\\\\Temp\\\\*", "*\\\\Client\\\\*", "C:\\\\PerfLogs\\\\*", "C:\\\\Users\\\\Public\\\\*", "C:\\\\Users\\\\Default\\\\*", "*.ps1", "*.vbs", "*.bat", "*.chm", "*.xml", "*.txt", "*.jsp", "*.jspx", "*.asp", "*.aspx", "*.php", "*.war", "*.hta", "*.lnk", "*.scf", "*.sct", "*.vbe", "*.wsf", "*.wsh"]
```


### grep
    
```
grep -P '^(?:.*C:\\Windows\\Temp\\\\.*|.*C:\\Temp\\\\.*|.*.*\\\\Client\\\\.*|.*C:\\PerfLogs\\\\.*|.*C:\\Users\\Public\\\\.*|.*C:\\Users\\Default\\\\.*|.*.*\\.ps1|.*.*\\.vbs|.*.*\\.bat|.*.*\\.chm|.*.*\\.xml|.*.*\\.txt|.*.*\\.jsp|.*.*\\.jspx|.*.*\\.asp|.*.*\\.aspx|.*.*\\.php|.*.*\\.war|.*.*\\.hta|.*.*\\.lnk|.*.*\\.scf|.*.*\\.sct|.*.*\\.vbe|.*.*\\.wsf|.*.*\\.wsh)'
```



