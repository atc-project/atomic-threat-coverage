| Title                    | Suspicious Eventlog Clear or Configuration Using Wevtutil       |
|:-------------------------|:------------------|
| **Description**          | Detects clearing or configuration of eventlogs uwing wevtutil, powershell and wmic. Might be used by ransomwares during the attack (seen by NotPetya and others) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1070.001: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070.001)</li><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1070.001: Clear Windows Event Logs](../Triggers/T1070.001.md)</li><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Admin activity</li><li>Scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/5b223758-07d6-4100-9e11-238cfdd0fe97.html](https://eqllib.readthedocs.io/en/latest/analytics/5b223758-07d6-4100-9e11-238cfdd0fe97.html)</li></ul>  |
| **Author**               | Ecco, Daniil Yugoslavskiy, oscd.community |
| Other Tags           | <ul><li>car.2016-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Eventlog Clear or Configuration Using Wevtutil
id: cc36992a-4671-4f21-a91d-6c2b72a2edf5
description: Detects clearing or configuration of eventlogs uwing wevtutil, powershell and wmic. Might be used by ransomwares during the attack (seen by NotPetya and others)
author: Ecco, Daniil Yugoslavskiy, oscd.community
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070/T1070.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/5b223758-07d6-4100-9e11-238cfdd0fe97.html
date: 2019/09/26
modified: 2019/11/11
tags:
    - attack.defense_evasion
    - attack.t1070.001
    - attack.t1070      # an old one
    - car.2016-04-002
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection_wevtutil_binary:
        Image|endswith: '\wevtutil.exe'
    selection_wevtutil_command:
        CommandLine|contains:
            - 'clear-log' # clears specified log
            - ' cl '        # short version of 'clear-log'
            - 'set-log'   # modifies config of specified log. could be uset to set it to a tiny size
            - ' sl '        # short version of 'set-log'
    selection_other_ps:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Clear-EventLog'
            - 'Remove-EventLog'
            - 'Limit-EventLog'
    selection_other_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains: ' ClearEventLog '
    condition: 1 of selection_other_* or (selection_wevtutil_binary and selection_wevtutil_command)
falsepositives:
    - Admin activity
    - Scripts and administrative tools used in the monitored environment

```





### powershell
    
```
Get-WinEvent | where {((($_.message -match "Image.*.*\\\\powershell.exe" -and ($_.message -match "CommandLine.*.*Clear-EventLog.*" -or $_.message -match "CommandLine.*.*Remove-EventLog.*" -or $_.message -match "CommandLine.*.*Limit-EventLog.*")) -or ($_.message -match "Image.*.*\\\\wmic.exe" -and $_.message -match "CommandLine.*.* ClearEventLog .*")) -or ($_.message -match "Image.*.*\\\\wevtutil.exe" -and ($_.message -match "CommandLine.*.*clear-log.*" -or $_.message -match "CommandLine.*.* cl .*" -or $_.message -match "CommandLine.*.*set-log.*" -or $_.message -match "CommandLine.*.* sl .*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(((winlog.event_data.Image.keyword:*\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:(*Clear\\-EventLog* OR *Remove\\-EventLog* OR *Limit\\-EventLog*)) OR (winlog.event_data.Image.keyword:*\\\\wmic.exe AND winlog.event_data.CommandLine.keyword:*\\ ClearEventLog\\ *)) OR (winlog.event_data.Image.keyword:*\\\\wevtutil.exe AND winlog.event_data.CommandLine.keyword:(*clear\\-log* OR *\\ cl\\ * OR *set\\-log* OR *\\ sl\\ *)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/cc36992a-4671-4f21-a91d-6c2b72a2edf5 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Eventlog Clear or Configuration Using Wevtutil",\n    "description": "Detects clearing or configuration of eventlogs uwing wevtutil, powershell and wmic. Might be used by ransomwares during the attack (seen by NotPetya and others)",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1070.001",\n      "attack.t1070",\n      "car.2016-04-002"\n    ],\n    "query": "(((winlog.event_data.Image.keyword:*\\\\\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:(*Clear\\\\-EventLog* OR *Remove\\\\-EventLog* OR *Limit\\\\-EventLog*)) OR (winlog.event_data.Image.keyword:*\\\\\\\\wmic.exe AND winlog.event_data.CommandLine.keyword:*\\\\ ClearEventLog\\\\ *)) OR (winlog.event_data.Image.keyword:*\\\\\\\\wevtutil.exe AND winlog.event_data.CommandLine.keyword:(*clear\\\\-log* OR *\\\\ cl\\\\ * OR *set\\\\-log* OR *\\\\ sl\\\\ *)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(((winlog.event_data.Image.keyword:*\\\\\\\\powershell.exe AND winlog.event_data.CommandLine.keyword:(*Clear\\\\-EventLog* OR *Remove\\\\-EventLog* OR *Limit\\\\-EventLog*)) OR (winlog.event_data.Image.keyword:*\\\\\\\\wmic.exe AND winlog.event_data.CommandLine.keyword:*\\\\ ClearEventLog\\\\ *)) OR (winlog.event_data.Image.keyword:*\\\\\\\\wevtutil.exe AND winlog.event_data.CommandLine.keyword:(*clear\\\\-log* OR *\\\\ cl\\\\ * OR *set\\\\-log* OR *\\\\ sl\\\\ *)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Eventlog Clear or Configuration Using Wevtutil\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(((Image.keyword:*\\\\powershell.exe AND CommandLine.keyword:(*Clear\\-EventLog* *Remove\\-EventLog* *Limit\\-EventLog*)) OR (Image.keyword:*\\\\wmic.exe AND CommandLine.keyword:* ClearEventLog *)) OR (Image.keyword:*\\\\wevtutil.exe AND CommandLine.keyword:(*clear\\-log* * cl * *set\\-log* * sl *)))
```


### splunk
    
```
(((Image="*\\\\powershell.exe" (CommandLine="*Clear-EventLog*" OR CommandLine="*Remove-EventLog*" OR CommandLine="*Limit-EventLog*")) OR (Image="*\\\\wmic.exe" CommandLine="* ClearEventLog *")) OR (Image="*\\\\wevtutil.exe" (CommandLine="*clear-log*" OR CommandLine="* cl *" OR CommandLine="*set-log*" OR CommandLine="* sl *")))
```


### logpoint
    
```
(((Image="*\\\\powershell.exe" CommandLine IN ["*Clear-EventLog*", "*Remove-EventLog*", "*Limit-EventLog*"]) OR (Image="*\\\\wmic.exe" CommandLine="* ClearEventLog *")) OR (Image="*\\\\wevtutil.exe" CommandLine IN ["*clear-log*", "* cl *", "*set-log*", "* sl *"]))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?:.*(?:.*(?=.*.*\\powershell\\.exe)(?=.*(?:.*.*Clear-EventLog.*|.*.*Remove-EventLog.*|.*.*Limit-EventLog.*)))|.*(?:.*(?=.*.*\\wmic\\.exe)(?=.*.* ClearEventLog .*))))|.*(?:.*(?=.*.*\\wevtutil\\.exe)(?=.*(?:.*.*clear-log.*|.*.* cl .*|.*.*set-log.*|.*.* sl .*)))))'
```



