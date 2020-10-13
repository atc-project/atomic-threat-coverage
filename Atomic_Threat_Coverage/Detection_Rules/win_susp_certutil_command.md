| Title                    | Suspicious Certutil Command       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with the built-in certutil utility |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/JohnLaTwC/status/835149808817991680](https://twitter.com/JohnLaTwC/status/835149808817991680)</li><li>[https://twitter.com/subTee/status/888102593838362624](https://twitter.com/subTee/status/888102593838362624)</li><li>[https://twitter.com/subTee/status/888071631528235010](https://twitter.com/subTee/status/888071631528235010)</li><li>[https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/](https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/)</li><li>[https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/](https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/)</li><li>[https://twitter.com/egre55/status/1087685529016193025](https://twitter.com/egre55/status/1087685529016193025)</li><li>[https://lolbas-project.github.io/lolbas/Binaries/Certutil/](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)</li></ul>  |
| **Author**               | Florian Roth, juju4, keepwatch |
| Other Tags           | <ul><li>attack.s0160</li><li>attack.g0007</li><li>attack.g0010</li><li>attack.g0045</li><li>attack.g0049</li><li>attack.g0075</li><li>attack.g0096</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Certutil Command
id: e011a729-98a6-4139-b5c4-bf6f6dd8239a
status: experimental
description: Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with
    the built-in certutil utility
author: Florian Roth, juju4, keepwatch
date: 2019/01/16
modified: 2020/09/05
references:
    - https://twitter.com/JohnLaTwC/status/835149808817991680
    - https://twitter.com/subTee/status/888102593838362624
    - https://twitter.com/subTee/status/888071631528235010
    - https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/
    - https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/
    - https://twitter.com/egre55/status/1087685529016193025
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -decode *'
            - '* /decode *'
            - '* -decodehex *'
            - '* /decodehex *'
            - '* -urlcache *'
            - '* /urlcache *'
            - '* -verifyctl *'
            - '* /verifyctl *'
            - '* -encode *'
            - '* /encode *'
            - '*certutil* -URL*'
            - '*certutil* /URL*'
            - '*certutil* -ping*'
            - '*certutil* /ping*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.command_and_control
    - attack.t1105
    - attack.s0160
    - attack.g0007
    - attack.g0010
    - attack.g0045
    - attack.g0049
    - attack.g0075
    - attack.g0096        
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.* -decode .*" -or $_.message -match "CommandLine.*.* /decode .*" -or $_.message -match "CommandLine.*.* -decodehex .*" -or $_.message -match "CommandLine.*.* /decodehex .*" -or $_.message -match "CommandLine.*.* -urlcache .*" -or $_.message -match "CommandLine.*.* /urlcache .*" -or $_.message -match "CommandLine.*.* -verifyctl .*" -or $_.message -match "CommandLine.*.* /verifyctl .*" -or $_.message -match "CommandLine.*.* -encode .*" -or $_.message -match "CommandLine.*.* /encode .*" -or $_.message -match "CommandLine.*.*certutil.* -URL.*" -or $_.message -match "CommandLine.*.*certutil.* /URL.*" -or $_.message -match "CommandLine.*.*certutil.* -ping.*" -or $_.message -match "CommandLine.*.*certutil.* /ping.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\ \-decode\ * OR *\ \/decode\ * OR *\ \-decodehex\ * OR *\ \/decodehex\ * OR *\ \-urlcache\ * OR *\ \/urlcache\ * OR *\ \-verifyctl\ * OR *\ \/verifyctl\ * OR *\ \-encode\ * OR *\ \/encode\ * OR *certutil*\ \-URL* OR *certutil*\ \/URL* OR *certutil*\ \-ping* OR *certutil*\ \/ping*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/e011a729-98a6-4139-b5c4-bf6f6dd8239a <<EOF
{
  "metadata": {
    "title": "Suspicious Certutil Command",
    "description": "Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with the built-in certutil utility",
    "tags": [
      "attack.defense_evasion",
      "attack.t1140",
      "attack.command_and_control",
      "attack.t1105",
      "attack.s0160",
      "attack.g0007",
      "attack.g0010",
      "attack.g0045",
      "attack.g0049",
      "attack.g0075",
      "attack.g0096"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\-decode\\ * OR *\\ \\/decode\\ * OR *\\ \\-decodehex\\ * OR *\\ \\/decodehex\\ * OR *\\ \\-urlcache\\ * OR *\\ \\/urlcache\\ * OR *\\ \\-verifyctl\\ * OR *\\ \\/verifyctl\\ * OR *\\ \\-encode\\ * OR *\\ \\/encode\\ * OR *certutil*\\ \\-URL* OR *certutil*\\ \\/URL* OR *certutil*\\ \\-ping* OR *certutil*\\ \\/ping*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\-decode\\ * OR *\\ \\/decode\\ * OR *\\ \\-decodehex\\ * OR *\\ \\/decodehex\\ * OR *\\ \\-urlcache\\ * OR *\\ \\/urlcache\\ * OR *\\ \\-verifyctl\\ * OR *\\ \\/verifyctl\\ * OR *\\ \\-encode\\ * OR *\\ \\/encode\\ * OR *certutil*\\ \\-URL* OR *certutil*\\ \\/URL* OR *certutil*\\ \\-ping* OR *certutil*\\ \\/ping*)",
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
        "subject": "Sigma Rule 'Suspicious Certutil Command'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
CommandLine.keyword:(* \-decode * * \/decode * * \-decodehex * * \/decodehex * * \-urlcache * * \/urlcache * * \-verifyctl * * \/verifyctl * * \-encode * * \/encode * *certutil* \-URL* *certutil* \/URL* *certutil* \-ping* *certutil* \/ping*)
```


### splunk
    
```
(CommandLine="* -decode *" OR CommandLine="* /decode *" OR CommandLine="* -decodehex *" OR CommandLine="* /decodehex *" OR CommandLine="* -urlcache *" OR CommandLine="* /urlcache *" OR CommandLine="* -verifyctl *" OR CommandLine="* /verifyctl *" OR CommandLine="* -encode *" OR CommandLine="* /encode *" OR CommandLine="*certutil* -URL*" OR CommandLine="*certutil* /URL*" OR CommandLine="*certutil* -ping*" OR CommandLine="*certutil* /ping*") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
CommandLine IN ["* -decode *", "* /decode *", "* -decodehex *", "* /decodehex *", "* -urlcache *", "* /urlcache *", "* -verifyctl *", "* /verifyctl *", "* -encode *", "* /encode *", "*certutil* -URL*", "*certutil* /URL*", "*certutil* -ping*", "*certutil* /ping*"]
```


### grep
    
```
grep -P '^(?:.*.* -decode .*|.*.* /decode .*|.*.* -decodehex .*|.*.* /decodehex .*|.*.* -urlcache .*|.*.* /urlcache .*|.*.* -verifyctl .*|.*.* /verifyctl .*|.*.* -encode .*|.*.* /encode .*|.*.*certutil.* -URL.*|.*.*certutil.* /URL.*|.*.*certutil.* -ping.*|.*.*certutil.* /ping.*)'
```



