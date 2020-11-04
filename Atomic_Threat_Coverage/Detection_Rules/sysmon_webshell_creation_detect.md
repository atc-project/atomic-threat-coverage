| Title                    | Windows Webshell Creation       |
|:-------------------------|:------------------|
| **Description**          | Possible webshell file creation on a static web site |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Legitimate administrator or developer creating legitimate executable files in a web application folder</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[PT ESC rule and personal experience](PT ESC rule and personal experience)</li></ul>  |
| **Author**               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Windows Webshell Creation
id: 39f1f9f2-9636-45de-98f6-a4046aa8e4b9
status: experimental
description: Possible webshell file creation on a static web site
references:
    - PT ESC rule and personal experience
author: Beyu Denis, oscd.community
date: 2019/10/22
modified: 2019/11/04
tags:
    - attack.persistence
    - attack.t1100
level: critical
logsource:
    product: windows
    service: sysmon
detection:
    selection_1:
        EventID: 11
    selection_2:
        TargetFilename|contains: '\inetpub\wwwroot\'
    selection_3:
        TargetFilename|contains:
            - '.asp'
            - '.ashx'
            - '.ph'
    selection_4:
        TargetFilename|contains:
            - '\www\'
            - '\htdocs\'
            - '\html\'
    selection_5:
        TargetFilename|contains: '.ph'
    selection_6:
        - TargetFilename|endswith: '.jsp'
        - TargetFilename|contains|all:
            - '\cgi-bin\'
            - '.pl'
    condition: selection_1 and ( selection_2 and selection_3 ) or
               selection_1 and ( selection_4 and selection_5 ) or
               selection_1 and selection_6
falsepositives:
    - Legitimate administrator or developer creating legitimate executable files in a web application folder

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and (((($_.message -match "TargetFilename.*.*\\inetpub\\wwwroot\\.*" -and ($_.message -match "TargetFilename.*.*.asp.*" -or $_.message -match "TargetFilename.*.*.ashx.*" -or $_.message -match "TargetFilename.*.*.ph.*")) -or (($_.message -match "TargetFilename.*.*\\www\\.*" -or $_.message -match "TargetFilename.*.*\\htdocs\\.*" -or $_.message -match "TargetFilename.*.*\\html\\.*") -and $_.message -match "TargetFilename.*.*.ph.*"))) -or ($_.message -match "TargetFilename.*.*.jsp" -or ($_.message -match "TargetFilename.*.*\\cgi-bin\\.*" -and $_.message -match "TargetFilename.*.*.pl.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"11" AND ((winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND ((winlog.event_data.TargetFilename.keyword:*\\inetpub\\wwwroot\* AND winlog.event_data.TargetFilename.keyword:(*.asp* OR *.ashx* OR *.ph*)) OR (winlog.event_data.TargetFilename.keyword:(*\\www\* OR *\\htdocs\* OR *\\html\*) AND winlog.event_data.TargetFilename.keyword:*.ph*))) OR (winlog.event_data.TargetFilename.keyword:*.jsp OR (winlog.event_data.TargetFilename.keyword:*\\cgi\-bin\* AND winlog.event_data.TargetFilename.keyword:*.pl*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/39f1f9f2-9636-45de-98f6-a4046aa8e4b9 <<EOF
{
  "metadata": {
    "title": "Windows Webshell Creation",
    "description": "Possible webshell file creation on a static web site",
    "tags": [
      "attack.persistence",
      "attack.t1100"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND ((winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND ((winlog.event_data.TargetFilename.keyword:*\\\\inetpub\\\\wwwroot\\* AND winlog.event_data.TargetFilename.keyword:(*.asp* OR *.ashx* OR *.ph*)) OR (winlog.event_data.TargetFilename.keyword:(*\\\\www\\* OR *\\\\htdocs\\* OR *\\\\html\\*) AND winlog.event_data.TargetFilename.keyword:*.ph*))) OR (winlog.event_data.TargetFilename.keyword:*.jsp OR (winlog.event_data.TargetFilename.keyword:*\\\\cgi\\-bin\\* AND winlog.event_data.TargetFilename.keyword:*.pl*))))"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND ((winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND ((winlog.event_data.TargetFilename.keyword:*\\\\inetpub\\\\wwwroot\\* AND winlog.event_data.TargetFilename.keyword:(*.asp* OR *.ashx* OR *.ph*)) OR (winlog.event_data.TargetFilename.keyword:(*\\\\www\\* OR *\\\\htdocs\\* OR *\\\\html\\*) AND winlog.event_data.TargetFilename.keyword:*.ph*))) OR (winlog.event_data.TargetFilename.keyword:*.jsp OR (winlog.event_data.TargetFilename.keyword:*\\\\cgi\\-bin\\* AND winlog.event_data.TargetFilename.keyword:*.pl*))))",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Windows Webshell Creation'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

```


### graylog
    
```
(EventID:"11" AND ((TargetFilename.keyword:*\\inetpub\\wwwroot\* AND TargetFilename.keyword:(*.asp* *.ashx* *.ph*)) OR (TargetFilename.keyword:(*\\www\* *\\htdocs\* *\\html\*) AND TargetFilename.keyword:*.ph*) OR TargetFilename.keyword:*.jsp OR (TargetFilename.keyword:*\\cgi\-bin\* AND TargetFilename.keyword:*.pl*)))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" ((source="WinEventLog:Microsoft-Windows-Sysmon/Operational" ((TargetFilename="*\\inetpub\\wwwroot\*" (TargetFilename="*.asp*" OR TargetFilename="*.ashx*" OR TargetFilename="*.ph*")) OR ((TargetFilename="*\\www\*" OR TargetFilename="*\\htdocs\*" OR TargetFilename="*\\html\*") TargetFilename="*.ph*"))) OR (TargetFilename="*.jsp" OR (TargetFilename="*\\cgi-bin\*" TargetFilename="*.pl*"))))
```


### logpoint
    
```
(event_id="11" ((TargetFilename="*\\inetpub\\wwwroot\*" TargetFilename IN ["*.asp*", "*.ashx*", "*.ph*"]) OR (TargetFilename IN ["*\\www\*", "*\\htdocs\*", "*\\html\*"] TargetFilename="*.ph*") OR TargetFilename="*.jsp" OR (TargetFilename="*\\cgi-bin\*" TargetFilename="*.pl*")))
```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*(?:.*(?:.*(?:.*(?=.*.*\inetpub\wwwroot\.*)(?=.*(?:.*.*\.asp.*|.*.*\.ashx.*|.*.*\.ph.*)))|.*(?:.*(?=.*(?:.*.*\www\.*|.*.*\htdocs\.*|.*.*\html\.*))(?=.*.*\.ph.*))|.*.*\.jsp|.*(?:.*(?=.*.*\cgi-bin\.*)(?=.*.*\.pl.*))))))'
```



