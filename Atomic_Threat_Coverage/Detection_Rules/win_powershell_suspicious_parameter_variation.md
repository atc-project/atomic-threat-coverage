| Title                    | Suspicious PowerShell Parameter Substring       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious PowerShell invocation with a parameter substring |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration tests</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier](http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier)</li></ul>  |
| **Author**               | Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix) |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Parameter Substring
id: 36210e0d-5b19-485d-a087-c096088885f0
status: experimental
description: Detects suspicious PowerShell invocation with a parameter substring
references:
    - http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier
tags:
    - attack.execution
    - attack.t1086
    - attack.t1059.001
author: Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix)
date: 2019/01/16
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\Powershell.exe'
        CommandLine:
            - ' -windowstyle h '
            - ' -windowstyl h'
            - ' -windowsty h'
            - ' -windowst h'
            - ' -windows h'
            - ' -windo h'
            - ' -wind h'
            - ' -win h'
            - ' -wi h'
            - ' -win h '
            - ' -win hi '
            - ' -win hid '
            - ' -win hidd '
            - ' -win hidde '
            - ' -NoPr '
            - ' -NoPro '
            - ' -NoProf '
            - ' -NoProfi '
            - ' -NoProfil '
            - ' -nonin '
            - ' -nonint '
            - ' -noninte '
            - ' -noninter '
            - ' -nonintera '
            - ' -noninterac '
            - ' -noninteract '
            - ' -noninteracti '
            - ' -noninteractiv '
            - ' -ec '
            - ' -encodedComman '
            - ' -encodedComma '
            - ' -encodedComm '
            - ' -encodedCom '
            - ' -encodedCo '
            - ' -encodedC '
            - ' -encoded '
            - ' -encode '
            - ' -encod '
            - ' -enco '
            - ' -en '
    condition: selection
falsepositives:
    - Penetration tests
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\Powershell.exe") -and ($_.message -match " -windowstyle h " -or $_.message -match " -windowstyl h" -or $_.message -match " -windowsty h" -or $_.message -match " -windowst h" -or $_.message -match " -windows h" -or $_.message -match " -windo h" -or $_.message -match " -wind h" -or $_.message -match " -win h" -or $_.message -match " -wi h" -or $_.message -match " -win h " -or $_.message -match " -win hi " -or $_.message -match " -win hid " -or $_.message -match " -win hidd " -or $_.message -match " -win hidde " -or $_.message -match " -NoPr " -or $_.message -match " -NoPro " -or $_.message -match " -NoProf " -or $_.message -match " -NoProfi " -or $_.message -match " -NoProfil " -or $_.message -match " -nonin " -or $_.message -match " -nonint " -or $_.message -match " -noninte " -or $_.message -match " -noninter " -or $_.message -match " -nonintera " -or $_.message -match " -noninterac " -or $_.message -match " -noninteract " -or $_.message -match " -noninteracti " -or $_.message -match " -noninteractiv " -or $_.message -match " -ec " -or $_.message -match " -encodedComman " -or $_.message -match " -encodedComma " -or $_.message -match " -encodedComm " -or $_.message -match " -encodedCom " -or $_.message -match " -encodedCo " -or $_.message -match " -encodedC " -or $_.message -match " -encoded " -or $_.message -match " -encode " -or $_.message -match " -encod " -or $_.message -match " -enco " -or $_.message -match " -en ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\Powershell.exe) AND winlog.event_data.CommandLine:("\ \-windowstyle\ h\ " OR "\ \-windowstyl\ h" OR "\ \-windowsty\ h" OR "\ \-windowst\ h" OR "\ \-windows\ h" OR "\ \-windo\ h" OR "\ \-wind\ h" OR "\ \-win\ h" OR "\ \-wi\ h" OR "\ \-win\ h\ " OR "\ \-win\ hi\ " OR "\ \-win\ hid\ " OR "\ \-win\ hidd\ " OR "\ \-win\ hidde\ " OR "\ \-NoPr\ " OR "\ \-NoPro\ " OR "\ \-NoProf\ " OR "\ \-NoProfi\ " OR "\ \-NoProfil\ " OR "\ \-nonin\ " OR "\ \-nonint\ " OR "\ \-noninte\ " OR "\ \-noninter\ " OR "\ \-nonintera\ " OR "\ \-noninterac\ " OR "\ \-noninteract\ " OR "\ \-noninteracti\ " OR "\ \-noninteractiv\ " OR "\ \-ec\ " OR "\ \-encodedComman\ " OR "\ \-encodedComma\ " OR "\ \-encodedComm\ " OR "\ \-encodedCom\ " OR "\ \-encodedCo\ " OR "\ \-encodedC\ " OR "\ \-encoded\ " OR "\ \-encode\ " OR "\ \-encod\ " OR "\ \-enco\ " OR "\ \-en\ "))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/36210e0d-5b19-485d-a087-c096088885f0 <<EOF
{
  "metadata": {
    "title": "Suspicious PowerShell Parameter Substring",
    "description": "Detects suspicious PowerShell invocation with a parameter substring",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\Powershell.exe) AND winlog.event_data.CommandLine:(\"\\ \\-windowstyle\\ h\\ \" OR \"\\ \\-windowstyl\\ h\" OR \"\\ \\-windowsty\\ h\" OR \"\\ \\-windowst\\ h\" OR \"\\ \\-windows\\ h\" OR \"\\ \\-windo\\ h\" OR \"\\ \\-wind\\ h\" OR \"\\ \\-win\\ h\" OR \"\\ \\-wi\\ h\" OR \"\\ \\-win\\ h\\ \" OR \"\\ \\-win\\ hi\\ \" OR \"\\ \\-win\\ hid\\ \" OR \"\\ \\-win\\ hidd\\ \" OR \"\\ \\-win\\ hidde\\ \" OR \"\\ \\-NoPr\\ \" OR \"\\ \\-NoPro\\ \" OR \"\\ \\-NoProf\\ \" OR \"\\ \\-NoProfi\\ \" OR \"\\ \\-NoProfil\\ \" OR \"\\ \\-nonin\\ \" OR \"\\ \\-nonint\\ \" OR \"\\ \\-noninte\\ \" OR \"\\ \\-noninter\\ \" OR \"\\ \\-nonintera\\ \" OR \"\\ \\-noninterac\\ \" OR \"\\ \\-noninteract\\ \" OR \"\\ \\-noninteracti\\ \" OR \"\\ \\-noninteractiv\\ \" OR \"\\ \\-ec\\ \" OR \"\\ \\-encodedComman\\ \" OR \"\\ \\-encodedComma\\ \" OR \"\\ \\-encodedComm\\ \" OR \"\\ \\-encodedCom\\ \" OR \"\\ \\-encodedCo\\ \" OR \"\\ \\-encodedC\\ \" OR \"\\ \\-encoded\\ \" OR \"\\ \\-encode\\ \" OR \"\\ \\-encod\\ \" OR \"\\ \\-enco\\ \" OR \"\\ \\-en\\ \"))"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\Powershell.exe) AND winlog.event_data.CommandLine:(\"\\ \\-windowstyle\\ h\\ \" OR \"\\ \\-windowstyl\\ h\" OR \"\\ \\-windowsty\\ h\" OR \"\\ \\-windowst\\ h\" OR \"\\ \\-windows\\ h\" OR \"\\ \\-windo\\ h\" OR \"\\ \\-wind\\ h\" OR \"\\ \\-win\\ h\" OR \"\\ \\-wi\\ h\" OR \"\\ \\-win\\ h\\ \" OR \"\\ \\-win\\ hi\\ \" OR \"\\ \\-win\\ hid\\ \" OR \"\\ \\-win\\ hidd\\ \" OR \"\\ \\-win\\ hidde\\ \" OR \"\\ \\-NoPr\\ \" OR \"\\ \\-NoPro\\ \" OR \"\\ \\-NoProf\\ \" OR \"\\ \\-NoProfi\\ \" OR \"\\ \\-NoProfil\\ \" OR \"\\ \\-nonin\\ \" OR \"\\ \\-nonint\\ \" OR \"\\ \\-noninte\\ \" OR \"\\ \\-noninter\\ \" OR \"\\ \\-nonintera\\ \" OR \"\\ \\-noninterac\\ \" OR \"\\ \\-noninteract\\ \" OR \"\\ \\-noninteracti\\ \" OR \"\\ \\-noninteractiv\\ \" OR \"\\ \\-ec\\ \" OR \"\\ \\-encodedComman\\ \" OR \"\\ \\-encodedComma\\ \" OR \"\\ \\-encodedComm\\ \" OR \"\\ \\-encodedCom\\ \" OR \"\\ \\-encodedCo\\ \" OR \"\\ \\-encodedC\\ \" OR \"\\ \\-encoded\\ \" OR \"\\ \\-encode\\ \" OR \"\\ \\-encod\\ \" OR \"\\ \\-enco\\ \" OR \"\\ \\-en\\ \"))",
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
        "subject": "Sigma Rule 'Suspicious PowerShell Parameter Substring'",
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
(Image.keyword:(*\\Powershell.exe) AND CommandLine:(" \-windowstyle h " " \-windowstyl h" " \-windowsty h" " \-windowst h" " \-windows h" " \-windo h" " \-wind h" " \-win h" " \-wi h" " \-win h " " \-win hi " " \-win hid " " \-win hidd " " \-win hidde " " \-NoPr " " \-NoPro " " \-NoProf " " \-NoProfi " " \-NoProfil " " \-nonin " " \-nonint " " \-noninte " " \-noninter " " \-nonintera " " \-noninterac " " \-noninteract " " \-noninteracti " " \-noninteractiv " " \-ec " " \-encodedComman " " \-encodedComma " " \-encodedComm " " \-encodedCom " " \-encodedCo " " \-encodedC " " \-encoded " " \-encode " " \-encod " " \-enco " " \-en "))
```


### splunk
    
```
((Image="*\\Powershell.exe") (CommandLine=" -windowstyle h " OR CommandLine=" -windowstyl h" OR CommandLine=" -windowsty h" OR CommandLine=" -windowst h" OR CommandLine=" -windows h" OR CommandLine=" -windo h" OR CommandLine=" -wind h" OR CommandLine=" -win h" OR CommandLine=" -wi h" OR CommandLine=" -win h " OR CommandLine=" -win hi " OR CommandLine=" -win hid " OR CommandLine=" -win hidd " OR CommandLine=" -win hidde " OR CommandLine=" -NoPr " OR CommandLine=" -NoPro " OR CommandLine=" -NoProf " OR CommandLine=" -NoProfi " OR CommandLine=" -NoProfil " OR CommandLine=" -nonin " OR CommandLine=" -nonint " OR CommandLine=" -noninte " OR CommandLine=" -noninter " OR CommandLine=" -nonintera " OR CommandLine=" -noninterac " OR CommandLine=" -noninteract " OR CommandLine=" -noninteracti " OR CommandLine=" -noninteractiv " OR CommandLine=" -ec " OR CommandLine=" -encodedComman " OR CommandLine=" -encodedComma " OR CommandLine=" -encodedComm " OR CommandLine=" -encodedCom " OR CommandLine=" -encodedCo " OR CommandLine=" -encodedC " OR CommandLine=" -encoded " OR CommandLine=" -encode " OR CommandLine=" -encod " OR CommandLine=" -enco " OR CommandLine=" -en "))
```


### logpoint
    
```
(event_id="1" Image IN ["*\\Powershell.exe"] CommandLine IN [" -windowstyle h ", " -windowstyl h", " -windowsty h", " -windowst h", " -windows h", " -windo h", " -wind h", " -win h", " -wi h", " -win h ", " -win hi ", " -win hid ", " -win hidd ", " -win hidde ", " -NoPr ", " -NoPro ", " -NoProf ", " -NoProfi ", " -NoProfil ", " -nonin ", " -nonint ", " -noninte ", " -noninter ", " -nonintera ", " -noninterac ", " -noninteract ", " -noninteracti ", " -noninteractiv ", " -ec ", " -encodedComman ", " -encodedComma ", " -encodedComm ", " -encodedCom ", " -encodedCo ", " -encodedC ", " -encoded ", " -encode ", " -encod ", " -enco ", " -en "])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\Powershell\.exe))(?=.*(?:.* -windowstyle h |.* -windowstyl h|.* -windowsty h|.* -windowst h|.* -windows h|.* -windo h|.* -wind h|.* -win h|.* -wi h|.* -win h |.* -win hi |.* -win hid |.* -win hidd |.* -win hidde |.* -NoPr |.* -NoPro |.* -NoProf |.* -NoProfi |.* -NoProfil |.* -nonin |.* -nonint |.* -noninte |.* -noninter |.* -nonintera |.* -noninterac |.* -noninteract |.* -noninteracti |.* -noninteractiv |.* -ec |.* -encodedComman |.* -encodedComma |.* -encodedComm |.* -encodedCom |.* -encodedCo |.* -encodedC |.* -encoded |.* -encode |.* -encod |.* -enco |.* -en )))'
```



