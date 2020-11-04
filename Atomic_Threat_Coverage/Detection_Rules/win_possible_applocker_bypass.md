| Title                    | Possible Applocker Bypass       |
|:-------------------------|:------------------|
| **Description**          | Detects execution of executables that can be used to bypass Applocker whitelisting |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1118: InstallUtil](https://attack.mitre.org/techniques/T1118)</li><li>[T1121: Regsvcs/Regasm](https://attack.mitre.org/techniques/T1121)</li><li>[T1127: Trusted Developer Utilities Proxy Execution](https://attack.mitre.org/techniques/T1127)</li><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1118: InstallUtil](../Triggers/T1118.md)</li><li>[T1121: Regsvcs/Regasm](../Triggers/T1121.md)</li><li>[T1127: Trusted Developer Utilities Proxy Execution](../Triggers/T1127.md)</li><li>[T1170: Mshta](../Triggers/T1170.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li><li>Using installutil to add features for .NET applications (primarly would occur in developer environments)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt](https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt)</li><li>[https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/](https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/)</li></ul>  |
| **Author**               | juju4 |


## Detection Rules

### Sigma rule

```
title: Possible Applocker Bypass
id: 82a19e3a-2bfe-4a91-8c0d-5d4c98fbb719
description: Detects execution of executables that can be used to bypass Applocker whitelisting
status: experimental
references:
    - https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt
    - https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/
author: juju4
date: 2019/01/16
tags:
    - attack.defense_evasion
    - attack.t1118
    - attack.t1121
    - attack.t1127
    - attack.t1170
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '\msdt.exe'
            - '\installutil.exe'
            - '\regsvcs.exe'
            - '\regasm.exe'
            # - '\regsvr32.exe'  # too many FPs, very noisy
            - '\msbuild.exe'
            - '\ieexec.exe'
            #- '\mshta.exe'
            #- '\csc.exe'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
    - Using installutil to add features for .NET applications (primarly would occur in developer environments)
level: low

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*\\msdt.exe.*" -or $_.message -match "CommandLine.*.*\\installutil.exe.*" -or $_.message -match "CommandLine.*.*\\regsvcs.exe.*" -or $_.message -match "CommandLine.*.*\\regasm.exe.*" -or $_.message -match "CommandLine.*.*\\msbuild.exe.*" -or $_.message -match "CommandLine.*.*\\ieexec.exe.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\\msdt.exe* OR *\\installutil.exe* OR *\\regsvcs.exe* OR *\\regasm.exe* OR *\\msbuild.exe* OR *\\ieexec.exe*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/82a19e3a-2bfe-4a91-8c0d-5d4c98fbb719 <<EOF
{
  "metadata": {
    "title": "Possible Applocker Bypass",
    "description": "Detects execution of executables that can be used to bypass Applocker whitelisting",
    "tags": [
      "attack.defense_evasion",
      "attack.t1118",
      "attack.t1121",
      "attack.t1127",
      "attack.t1170"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\\\msdt.exe* OR *\\\\installutil.exe* OR *\\\\regsvcs.exe* OR *\\\\regasm.exe* OR *\\\\msbuild.exe* OR *\\\\ieexec.exe*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\\\msdt.exe* OR *\\\\installutil.exe* OR *\\\\regsvcs.exe* OR *\\\\regasm.exe* OR *\\\\msbuild.exe* OR *\\\\ieexec.exe*)",
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
        "subject": "Sigma Rule 'Possible Applocker Bypass'",
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
CommandLine.keyword:(*\\msdt.exe* *\\installutil.exe* *\\regsvcs.exe* *\\regasm.exe* *\\msbuild.exe* *\\ieexec.exe*)
```


### splunk
    
```
(CommandLine="*\\msdt.exe*" OR CommandLine="*\\installutil.exe*" OR CommandLine="*\\regsvcs.exe*" OR CommandLine="*\\regasm.exe*" OR CommandLine="*\\msbuild.exe*" OR CommandLine="*\\ieexec.exe*")
```


### logpoint
    
```
CommandLine IN ["*\\msdt.exe*", "*\\installutil.exe*", "*\\regsvcs.exe*", "*\\regasm.exe*", "*\\msbuild.exe*", "*\\ieexec.exe*"]
```


### grep
    
```
grep -P '^(?:.*.*\msdt\.exe.*|.*.*\installutil\.exe.*|.*.*\regsvcs\.exe.*|.*.*\regasm\.exe.*|.*.*\msbuild\.exe.*|.*.*\ieexec\.exe.*)'
```



