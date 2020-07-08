| Title                    | Reconnaissance Activity with Net Command       |
|:-------------------------|:------------------|
| **Description**          | Detects a set of commands often used in recon stages by different attack groups |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li><li>[T1082: System Information Discovery](https://attack.mitre.org/techniques/T1082)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1082: System Information Discovery](../Triggers/T1082.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/haroonmeer/status/939099379834658817](https://twitter.com/haroonmeer/status/939099379834658817)</li><li>[https://twitter.com/c_APT_ure/status/939475433711722497](https://twitter.com/c_APT_ure/status/939475433711722497)</li><li>[https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html](https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html)</li></ul>  |
| **Author**               | Florian Roth, Markus Neis |
| Other Tags           | <ul><li>car.2016-03-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Reconnaissance Activity with Net Command
id: 2887e914-ce96-435f-8105-593937e90757
status: experimental
description: Detects a set of commands often used in recon stages by different attack groups
references:
    - https://twitter.com/haroonmeer/status/939099379834658817
    - https://twitter.com/c_APT_ure/status/939475433711722497
    - https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html
author: Florian Roth, Markus Neis
date: 2018/08/22
modified: 2018/12/11
tags:
    - attack.discovery
    - attack.t1087
    - attack.t1082
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - tasklist
            - net time
            - systeminfo
            - whoami
            - nbtstat
            - net start
            - '*\net1 start'
            - qprocess
            - nslookup
            - hostname.exe
            - '*\net1 user /domain'
            - '*\net1 group /domain'
            - '*\net1 group "domain admins" /domain'
            - '*\net1 group "Exchange Trusted Subsystem" /domain'
            - '*\net1 accounts /domain'
            - '*\net1 user net localgroup administrators'
            - netstat -an
    timeframe: 15s
    condition: selection | count() by CommandLine > 4
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "tasklist" -or $_.message -match "net time" -or $_.message -match "systeminfo" -or $_.message -match "whoami" -or $_.message -match "nbtstat" -or $_.message -match "net start" -or $_.message -match "CommandLine.*.*\\net1 start" -or $_.message -match "qprocess" -or $_.message -match "nslookup" -or $_.message -match "hostname.exe" -or $_.message -match "CommandLine.*.*\\net1 user /domain" -or $_.message -match "CommandLine.*.*\\net1 group /domain" -or $_.message -match "CommandLine.*.*\\net1 group \"domain admins\" /domain" -or $_.message -match "CommandLine.*.*\\net1 group \"Exchange Trusted Subsystem\" /domain" -or $_.message -match "CommandLine.*.*\\net1 accounts /domain" -or $_.message -match "CommandLine.*.*\\net1 user net localgroup administrators" -or $_.message -match "netstat -an")) }  | group-object CommandLine | where { $_.count -gt 4 } | select name,count | sort -desc
```


### es-qs
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/process_creation/win_susp_commands_recon_activity.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/2887e914-ce96-435f-8105-593937e90757 <<EOF
{
  "metadata": {
    "title": "Reconnaissance Activity with Net Command",
    "description": "Detects a set of commands often used in recon stages by different attack groups",
    "tags": [
      "attack.discovery",
      "attack.t1087",
      "attack.t1082",
      "car.2016-03-001"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(tasklist OR net\\ time OR systeminfo OR whoami OR nbtstat OR net\\ start OR *\\\\net1\\ start OR qprocess OR nslookup OR hostname.exe OR *\\\\net1\\ user\\ \\/domain OR *\\\\net1\\ group\\ \\/domain OR *\\\\net1\\ group\\ \\\"domain\\ admins\\\"\\ \\/domain OR *\\\\net1\\ group\\ \\\"Exchange\\ Trusted\\ Subsystem\\\"\\ \\/domain OR *\\\\net1\\ accounts\\ \\/domain OR *\\\\net1\\ user\\ net\\ localgroup\\ administrators OR netstat\\ \\-an)"
  },
  "trigger": {
    "schedule": {
      "interval": "15s"
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
                    "query": "winlog.event_data.CommandLine.keyword:(tasklist OR net\\ time OR systeminfo OR whoami OR nbtstat OR net\\ start OR *\\\\net1\\ start OR qprocess OR nslookup OR hostname.exe OR *\\\\net1\\ user\\ \\/domain OR *\\\\net1\\ group\\ \\/domain OR *\\\\net1\\ group\\ \\\"domain\\ admins\\\"\\ \\/domain OR *\\\\net1\\ group\\ \\\"Exchange\\ Trusted\\ Subsystem\\\"\\ \\/domain OR *\\\\net1\\ accounts\\ \\/domain OR *\\\\net1\\ user\\ net\\ localgroup\\ administrators OR netstat\\ \\-an)",
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
          },
          "aggs": {
            "by": {
              "terms": {
                "field": "winlog.event_data.CommandLine",
                "size": 10,
                "order": {
                  "_count": "desc"
                },
                "min_doc_count": 5
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
      "ctx.payload.aggregations.by.buckets.0.doc_count": {
        "gt": 4
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
        "subject": "Sigma Rule 'Reconnaissance Activity with Net Command'",
        "body": "Hits:\n{{#aggregations.by.buckets}}\n {{key}} {{doc_count}}\n{{/aggregations.by.buckets}}\n",
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/process_creation/win_susp_commands_recon_activity.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### splunk
    
```
(CommandLine="tasklist" OR CommandLine="net time" OR CommandLine="systeminfo" OR CommandLine="whoami" OR CommandLine="nbtstat" OR CommandLine="net start" OR CommandLine="*\\net1 start" OR CommandLine="qprocess" OR CommandLine="nslookup" OR CommandLine="hostname.exe" OR CommandLine="*\\net1 user /domain" OR CommandLine="*\\net1 group /domain" OR CommandLine="*\\net1 group \"domain admins\" /domain" OR CommandLine="*\\net1 group \"Exchange Trusted Subsystem\" /domain" OR CommandLine="*\\net1 accounts /domain" OR CommandLine="*\\net1 user net localgroup administrators" OR CommandLine="netstat -an") | eventstats count as val by CommandLine| search val > 4
```


### logpoint
    
```
(event_id="1" CommandLine IN ["tasklist", "net time", "systeminfo", "whoami", "nbtstat", "net start", "*\\net1 start", "qprocess", "nslookup", "hostname.exe", "*\\net1 user /domain", "*\\net1 group /domain", "*\\net1 group \"domain admins\" /domain", "*\\net1 group \"Exchange Trusted Subsystem\" /domain", "*\\net1 accounts /domain", "*\\net1 user net localgroup administrators", "netstat -an"]) | chart count() as val by CommandLine | search val > 4
```


### grep
    
```
grep -P '^(?:.*tasklist|.*net time|.*systeminfo|.*whoami|.*nbtstat|.*net start|.*.*\net1 start|.*qprocess|.*nslookup|.*hostname\.exe|.*.*\net1 user /domain|.*.*\net1 group /domain|.*.*\net1 group "domain admins" /domain|.*.*\net1 group "Exchange Trusted Subsystem" /domain|.*.*\net1 accounts /domain|.*.*\net1 user net localgroup administrators|.*netstat -an)'
```



