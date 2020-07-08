| Title                    | Domain Trust Discovery       |
|:-------------------------|:------------------|
| **Description**          | Identifies execution of nltest.exe and dsquery.exe for domain trust discovery. This technique is used by attackers to enumerate Active Directory trusts. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1482: Domain Trust Discovery](https://attack.mitre.org/techniques/T1482)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1482: Domain Trust Discovery](../Triggers/T1482.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate use of the utilities by legitimate user for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/03e231a6-74bc-467a-acb1-e5676b0fb55e.html](https://eqllib.readthedocs.io/en/latest/analytics/03e231a6-74bc-467a-acb1-e5676b0fb55e.html)</li></ul>  |
| **Author**               | E.M. Anhaus (orignally from Atomic Blue Detections, Tony Lambert), oscd.community |


## Detection Rules

### Sigma rule

```
title: Domain Trust Discovery
id: 3bad990e-4848-4a78-9530-b427d854aac0
description: Identifies execution of nltest.exe and dsquery.exe for domain trust discovery. This technique is used by attackers to enumerate Active Directory trusts.
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Tony Lambert), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.md
    - https://eqllib.readthedocs.io/en/latest/analytics/03e231a6-74bc-467a-acb1-e5676b0fb55e.html
tags:
    - attack.discovery
    - attack.t1482
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: '\nltest.exe'
        CommandLine|contains: 'domain_trusts'
      - Image|endswith: '\dsquery.exe'
        CommandLine|contains: 'trustedDomain'
    condition: selection
falsepositives:
    - Legitimate use of the utilities by legitimate user for legitimate reason
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\nltest.exe" -and $_.message -match "CommandLine.*.*domain_trusts.*") -or ($_.message -match "Image.*.*\\dsquery.exe" -and $_.message -match "CommandLine.*.*trustedDomain.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\nltest.exe AND winlog.event_data.CommandLine.keyword:*domain_trusts*) OR (winlog.event_data.Image.keyword:*\\dsquery.exe AND winlog.event_data.CommandLine.keyword:*trustedDomain*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3bad990e-4848-4a78-9530-b427d854aac0 <<EOF
{
  "metadata": {
    "title": "Domain Trust Discovery",
    "description": "Identifies execution of nltest.exe and dsquery.exe for domain trust discovery. This technique is used by attackers to enumerate Active Directory trusts.",
    "tags": [
      "attack.discovery",
      "attack.t1482"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\nltest.exe AND winlog.event_data.CommandLine.keyword:*domain_trusts*) OR (winlog.event_data.Image.keyword:*\\\\dsquery.exe AND winlog.event_data.CommandLine.keyword:*trustedDomain*))"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\nltest.exe AND winlog.event_data.CommandLine.keyword:*domain_trusts*) OR (winlog.event_data.Image.keyword:*\\\\dsquery.exe AND winlog.event_data.CommandLine.keyword:*trustedDomain*))",
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
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'Domain Trust Discovery'",
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
((Image.keyword:*\\nltest.exe AND CommandLine.keyword:*domain_trusts*) OR (Image.keyword:*\\dsquery.exe AND CommandLine.keyword:*trustedDomain*))
```


### splunk
    
```
((Image="*\\nltest.exe" CommandLine="*domain_trusts*") OR (Image="*\\dsquery.exe" CommandLine="*trustedDomain*"))
```


### logpoint
    
```
(event_id="1" ((Image="*\\nltest.exe" CommandLine="*domain_trusts*") OR (Image="*\\dsquery.exe" CommandLine="*trustedDomain*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\nltest\.exe)(?=.*.*domain_trusts.*))|.*(?:.*(?=.*.*\dsquery\.exe)(?=.*.*trustedDomain.*))))'
```



