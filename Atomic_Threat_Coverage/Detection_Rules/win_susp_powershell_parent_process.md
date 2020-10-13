| Title                    | Suspicious PowerShell Parent Process       |
|:-------------------------|:------------------|
| **Description**          | Detects a suspicious parents of powershell.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Other scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=26](https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=26)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, Harish Segar (rule) |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Parent Process
id: 754ed792-634f-40ae-b3bc-e0448d33f695
description: Detects a suspicious parents of powershell.exe
status: experimental
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=26
author: Teymur Kheirkhabarov, Harish Segar (rule)
date: 2020/03/20
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086      # an old one   
logsource:
    category: process_creation
    product: windows
detection:
    selection_image1:
        - ParentImage|endswith:
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\regsvr32.exe'
            - '\services.exe'
            - '\winword.exe'
            - '\wmiprvse.exe'
            - '\powerpnt.exe'
            - '\excel.exe'
            - '\msaccess.exe'
            - '\mspub.exe'
            - '\visio.exe'
            - '\outlook.exe'
            - '\amigo.exe'
            - '\chrome.exe'
            - '\firefox.exe'
            - '\iexplore.exe'
            - '\microsoftedgecp.exe'
            - '\microsoftedge.exe'
            - '\browser.exe'
            - '\vivaldi.exe'
            - '\safari.exe'
            - '\sqlagent.exe'
            - '\sqlserver.exe'
            - '\sqlservr.exe'
            - '\w3wp.exe'
            - '\httpd.exe'
            - '\nginx.exe'
            - '\php-cgi.exe'
            - '\jbosssvc.exe'
            - "MicrosoftEdgeSH.exe"
        - ParentImage|contains: "tomcat"
    selection_powershell:
        - CommandLine|contains:
              - "powershell"
              - "pwsh"
        - Description: "Windows PowerShell"
        - Product: "PowerShell Core 6"
    condition: all of them
falsepositives:
    - Other scripts
level: medium

```





### powershell
    
```
Get-WinEvent | where {((($_.message -match "ParentImage.*.*\\mshta.exe" -or $_.message -match "ParentImage.*.*\\rundll32.exe" -or $_.message -match "ParentImage.*.*\\regsvr32.exe" -or $_.message -match "ParentImage.*.*\\services.exe" -or $_.message -match "ParentImage.*.*\\winword.exe" -or $_.message -match "ParentImage.*.*\\wmiprvse.exe" -or $_.message -match "ParentImage.*.*\\powerpnt.exe" -or $_.message -match "ParentImage.*.*\\excel.exe" -or $_.message -match "ParentImage.*.*\\msaccess.exe" -or $_.message -match "ParentImage.*.*\\mspub.exe" -or $_.message -match "ParentImage.*.*\\visio.exe" -or $_.message -match "ParentImage.*.*\\outlook.exe" -or $_.message -match "ParentImage.*.*\\amigo.exe" -or $_.message -match "ParentImage.*.*\\chrome.exe" -or $_.message -match "ParentImage.*.*\\firefox.exe" -or $_.message -match "ParentImage.*.*\\iexplore.exe" -or $_.message -match "ParentImage.*.*\\microsoftedgecp.exe" -or $_.message -match "ParentImage.*.*\\microsoftedge.exe" -or $_.message -match "ParentImage.*.*\\browser.exe" -or $_.message -match "ParentImage.*.*\\vivaldi.exe" -or $_.message -match "ParentImage.*.*\\safari.exe" -or $_.message -match "ParentImage.*.*\\sqlagent.exe" -or $_.message -match "ParentImage.*.*\\sqlserver.exe" -or $_.message -match "ParentImage.*.*\\sqlservr.exe" -or $_.message -match "ParentImage.*.*\\w3wp.exe" -or $_.message -match "ParentImage.*.*\\httpd.exe" -or $_.message -match "ParentImage.*.*\\nginx.exe" -or $_.message -match "ParentImage.*.*\\php-cgi.exe" -or $_.message -match "ParentImage.*.*\\jbosssvc.exe" -or $_.message -match "ParentImage.*.*MicrosoftEdgeSH.exe") -or $_.message -match "ParentImage.*.*tomcat.*") -and (($_.message -match "CommandLine.*.*powershell.*" -or $_.message -match "CommandLine.*.*pwsh.*") -or $_.message -match "Description.*Windows PowerShell" -or $_.message -match "Product.*PowerShell Core 6")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.ParentImage.keyword:(*\\mshta.exe OR *\\rundll32.exe OR *\\regsvr32.exe OR *\\services.exe OR *\\winword.exe OR *\\wmiprvse.exe OR *\\powerpnt.exe OR *\\excel.exe OR *\\msaccess.exe OR *\\mspub.exe OR *\\visio.exe OR *\\outlook.exe OR *\\amigo.exe OR *\\chrome.exe OR *\\firefox.exe OR *\\iexplore.exe OR *\\microsoftedgecp.exe OR *\\microsoftedge.exe OR *\\browser.exe OR *\\vivaldi.exe OR *\\safari.exe OR *\\sqlagent.exe OR *\\sqlserver.exe OR *\\sqlservr.exe OR *\\w3wp.exe OR *\\httpd.exe OR *\\nginx.exe OR *\\php\-cgi.exe OR *\\jbosssvc.exe OR *MicrosoftEdgeSH.exe) OR winlog.event_data.ParentImage.keyword:*tomcat*) AND (winlog.event_data.CommandLine.keyword:(*powershell* OR *pwsh*) OR winlog.event_data.Description:"Windows\ PowerShell" OR Product:"PowerShell\ Core\ 6"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/754ed792-634f-40ae-b3bc-e0448d33f695 <<EOF
{
  "metadata": {
    "title": "Suspicious PowerShell Parent Process",
    "description": "Detects a suspicious parents of powershell.exe",
    "tags": [
      "attack.execution",
      "attack.t1059.001",
      "attack.t1086"
    ],
    "query": "((winlog.event_data.ParentImage.keyword:(*\\\\mshta.exe OR *\\\\rundll32.exe OR *\\\\regsvr32.exe OR *\\\\services.exe OR *\\\\winword.exe OR *\\\\wmiprvse.exe OR *\\\\powerpnt.exe OR *\\\\excel.exe OR *\\\\msaccess.exe OR *\\\\mspub.exe OR *\\\\visio.exe OR *\\\\outlook.exe OR *\\\\amigo.exe OR *\\\\chrome.exe OR *\\\\firefox.exe OR *\\\\iexplore.exe OR *\\\\microsoftedgecp.exe OR *\\\\microsoftedge.exe OR *\\\\browser.exe OR *\\\\vivaldi.exe OR *\\\\safari.exe OR *\\\\sqlagent.exe OR *\\\\sqlserver.exe OR *\\\\sqlservr.exe OR *\\\\w3wp.exe OR *\\\\httpd.exe OR *\\\\nginx.exe OR *\\\\php\\-cgi.exe OR *\\\\jbosssvc.exe OR *MicrosoftEdgeSH.exe) OR winlog.event_data.ParentImage.keyword:*tomcat*) AND (winlog.event_data.CommandLine.keyword:(*powershell* OR *pwsh*) OR winlog.event_data.Description:\"Windows\\ PowerShell\" OR Product:\"PowerShell\\ Core\\ 6\"))"
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
                    "query": "((winlog.event_data.ParentImage.keyword:(*\\\\mshta.exe OR *\\\\rundll32.exe OR *\\\\regsvr32.exe OR *\\\\services.exe OR *\\\\winword.exe OR *\\\\wmiprvse.exe OR *\\\\powerpnt.exe OR *\\\\excel.exe OR *\\\\msaccess.exe OR *\\\\mspub.exe OR *\\\\visio.exe OR *\\\\outlook.exe OR *\\\\amigo.exe OR *\\\\chrome.exe OR *\\\\firefox.exe OR *\\\\iexplore.exe OR *\\\\microsoftedgecp.exe OR *\\\\microsoftedge.exe OR *\\\\browser.exe OR *\\\\vivaldi.exe OR *\\\\safari.exe OR *\\\\sqlagent.exe OR *\\\\sqlserver.exe OR *\\\\sqlservr.exe OR *\\\\w3wp.exe OR *\\\\httpd.exe OR *\\\\nginx.exe OR *\\\\php\\-cgi.exe OR *\\\\jbosssvc.exe OR *MicrosoftEdgeSH.exe) OR winlog.event_data.ParentImage.keyword:*tomcat*) AND (winlog.event_data.CommandLine.keyword:(*powershell* OR *pwsh*) OR winlog.event_data.Description:\"Windows\\ PowerShell\" OR Product:\"PowerShell\\ Core\\ 6\"))",
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
        "subject": "Sigma Rule 'Suspicious PowerShell Parent Process'",
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
((ParentImage.keyword:(*\\mshta.exe *\\rundll32.exe *\\regsvr32.exe *\\services.exe *\\winword.exe *\\wmiprvse.exe *\\powerpnt.exe *\\excel.exe *\\msaccess.exe *\\mspub.exe *\\visio.exe *\\outlook.exe *\\amigo.exe *\\chrome.exe *\\firefox.exe *\\iexplore.exe *\\microsoftedgecp.exe *\\microsoftedge.exe *\\browser.exe *\\vivaldi.exe *\\safari.exe *\\sqlagent.exe *\\sqlserver.exe *\\sqlservr.exe *\\w3wp.exe *\\httpd.exe *\\nginx.exe *\\php\-cgi.exe *\\jbosssvc.exe *MicrosoftEdgeSH.exe) OR ParentImage.keyword:*tomcat*) AND (CommandLine.keyword:(*powershell* *pwsh*) OR Description:"Windows PowerShell" OR Product:"PowerShell Core 6"))
```


### splunk
    
```
(((ParentImage="*\\mshta.exe" OR ParentImage="*\\rundll32.exe" OR ParentImage="*\\regsvr32.exe" OR ParentImage="*\\services.exe" OR ParentImage="*\\winword.exe" OR ParentImage="*\\wmiprvse.exe" OR ParentImage="*\\powerpnt.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\msaccess.exe" OR ParentImage="*\\mspub.exe" OR ParentImage="*\\visio.exe" OR ParentImage="*\\outlook.exe" OR ParentImage="*\\amigo.exe" OR ParentImage="*\\chrome.exe" OR ParentImage="*\\firefox.exe" OR ParentImage="*\\iexplore.exe" OR ParentImage="*\\microsoftedgecp.exe" OR ParentImage="*\\microsoftedge.exe" OR ParentImage="*\\browser.exe" OR ParentImage="*\\vivaldi.exe" OR ParentImage="*\\safari.exe" OR ParentImage="*\\sqlagent.exe" OR ParentImage="*\\sqlserver.exe" OR ParentImage="*\\sqlservr.exe" OR ParentImage="*\\w3wp.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\jbosssvc.exe" OR ParentImage="*MicrosoftEdgeSH.exe") OR ParentImage="*tomcat*") ((CommandLine="*powershell*" OR CommandLine="*pwsh*") OR Description="Windows PowerShell" OR Product="PowerShell Core 6"))
```


### logpoint
    
```
((ParentImage IN ["*\\mshta.exe", "*\\rundll32.exe", "*\\regsvr32.exe", "*\\services.exe", "*\\winword.exe", "*\\wmiprvse.exe", "*\\powerpnt.exe", "*\\excel.exe", "*\\msaccess.exe", "*\\mspub.exe", "*\\visio.exe", "*\\outlook.exe", "*\\amigo.exe", "*\\chrome.exe", "*\\firefox.exe", "*\\iexplore.exe", "*\\microsoftedgecp.exe", "*\\microsoftedge.exe", "*\\browser.exe", "*\\vivaldi.exe", "*\\safari.exe", "*\\sqlagent.exe", "*\\sqlserver.exe", "*\\sqlservr.exe", "*\\w3wp.exe", "*\\httpd.exe", "*\\nginx.exe", "*\\php-cgi.exe", "*\\jbosssvc.exe", "*MicrosoftEdgeSH.exe"] OR ParentImage="*tomcat*") (CommandLine IN ["*powershell*", "*pwsh*"] OR Description="Windows PowerShell" OR Product="PowerShell Core 6"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*(?:.*.*\mshta\.exe|.*.*\rundll32\.exe|.*.*\regsvr32\.exe|.*.*\services\.exe|.*.*\winword\.exe|.*.*\wmiprvse\.exe|.*.*\powerpnt\.exe|.*.*\excel\.exe|.*.*\msaccess\.exe|.*.*\mspub\.exe|.*.*\visio\.exe|.*.*\outlook\.exe|.*.*\amigo\.exe|.*.*\chrome\.exe|.*.*\firefox\.exe|.*.*\iexplore\.exe|.*.*\microsoftedgecp\.exe|.*.*\microsoftedge\.exe|.*.*\browser\.exe|.*.*\vivaldi\.exe|.*.*\safari\.exe|.*.*\sqlagent\.exe|.*.*\sqlserver\.exe|.*.*\sqlservr\.exe|.*.*\w3wp\.exe|.*.*\httpd\.exe|.*.*\nginx\.exe|.*.*\php-cgi\.exe|.*.*\jbosssvc\.exe|.*.*MicrosoftEdgeSH\.exe)|.*.*tomcat.*)))(?=.*(?:.*(?:.*(?:.*.*powershell.*|.*.*pwsh.*)|.*Windows PowerShell|.*PowerShell Core 6))))'
```



