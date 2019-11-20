| Title                | Squirrel Lolbin                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Possible Squirrel Packages Manager as Lolbin                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>1Clipboard</li><li>Beaker Browser</li><li>Caret</li><li>Collectie</li><li>Discord</li><li>Figma</li><li>Flow</li><li>Ghost</li><li>GitHub Desktop</li><li>GitKraken</li><li>Hyper</li><li>Insomnia</li><li>JIBO</li><li>Kap</li><li>Kitematic</li><li>Now Desktop</li><li>Postman</li><li>PostmanCanary</li><li>Rambox</li><li>Simplenote</li><li>Skype</li><li>Slack</li><li>SourceTree</li><li>Stride</li><li>Svgsus</li><li>WebTorrent</li><li>WhatsApp</li><li>WordPress.com</li><li>atom</li><li>gitkraken</li><li>slack</li><li>teams</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/](http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/)</li><li>[http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/](http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/)</li></ul>  |
| Author               | Karneades / Markus Neis |


## Detection Rules

### Sigma rule

```
title: Squirrel Lolbin
id: fa4b21c9-0057-4493-b289-2556416ae4d7
status: experimental
description: Detects Possible Squirrel Packages Manager as Lolbin
references:
    - http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/
    - http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/
tags:
    - attack.execution
author: Karneades / Markus Neis
falsepositives:
    - 1Clipboard
    - Beaker Browser
    - Caret
    - Collectie
    - Discord
    - Figma
    - Flow
    - Ghost
    - GitHub Desktop
    - GitKraken
    - Hyper
    - Insomnia
    - JIBO
    - Kap
    - Kitematic
    - Now Desktop
    - Postman
    - PostmanCanary
    - Rambox
    - Simplenote
    - Skype
    - Slack
    - SourceTree
    - Stride
    - Svgsus
    - WebTorrent
    - WhatsApp
    - WordPress.com
    - atom
    - gitkraken
    - slack
    - teams
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\update.exe'                           # Check if folder Name matches executed binary  \\(?P<first>[^\\]*)\\Update.*Start.{2}(?P<second>\1)\.exe (example: https://regex101.com/r/SGSQGz/2)
        CommandLine:
            - '*--processStart*.exe*'
            - '*--processStartAndWait*.exe*'
            - '*–createShortcut*.exe*'
    condition: selection 
  
    

```





### splunk
    
```
((Image="*\\\\update.exe") (CommandLine="*--processStart*.exe*" OR CommandLine="*--processStartAndWait*.exe*" OR CommandLine="*\xe2\x80\x93createShortcut*.exe*"))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Squirrel Lolbin]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Squirrel Lolbin status: experimental \
description: Detects Possible Squirrel Packages Manager as Lolbin \
references: ['http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/', 'http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/'] \
tags: ['attack.execution'] \
author: Karneades / Markus Neis \
date:  \
falsepositives: ['1Clipboard', 'Beaker Browser', 'Caret', 'Collectie', 'Discord', 'Figma', 'Flow', 'Ghost', 'GitHub Desktop', 'GitKraken', 'Hyper', 'Insomnia', 'JIBO', 'Kap', 'Kitematic', 'Now Desktop', 'Postman', 'PostmanCanary', 'Rambox', 'Simplenote', 'Skype', 'Slack', 'SourceTree', 'Stride', 'Svgsus', 'WebTorrent', 'WhatsApp', 'WordPress.com', 'atom', 'gitkraken', 'slack', 'teams'] \
level: high
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects Possible Squirrel Packages Manager as Lolbin
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\update.exe") (CommandLine="*--processStart*.exe*" OR CommandLine="*--processStartAndWait*.exe*" OR CommandLine="*–createShortcut*.exe*")) | stats values(*) AS * by _time | search NOT [| inputlookup Squirrel_Lolbin_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,level=high"
```
