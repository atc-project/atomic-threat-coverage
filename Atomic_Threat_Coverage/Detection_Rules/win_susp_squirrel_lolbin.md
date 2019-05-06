| Title                | Squirrel Lolbin                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Possible Squirrel Packages Manager as Lolbin                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>1Clipboard</li><li>Beaker Browser</li><li>Caret</li><li>Collectie</li><li>Discord</li><li>Figma</li><li>Flow</li><li>Ghost</li><li>GitHub Desktop</li><li>GitKraken</li><li>Hyper</li><li>Insomnia</li><li>JIBO</li><li>Kap</li><li>Kitematic</li><li>Now Desktop</li><li>Postman</li><li>PostmanCanary</li><li>Rambox</li><li>Simplenote</li><li>Skype</li><li>Slack</li><li>SourceTree</li><li>Stride</li><li>Svgsus</li><li>WebTorrent</li><li>WhatsApp</li><li>WordPress.com</li><li>atom</li><li>gitkraken</li><li>slack</li><li>teams</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/](http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/)</li></ul>                                                          |
| Author               | Karneades / Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Squirrel Lolbin
status: experimental
description: Detects Possible Squirrel Packages Manager as Lolbin 
references:
    - http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/  
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
            - '*–createShortcut*.exe*'
    condition: selection 
  
    
```





### es-qs
    
```

```


### xpack-watcher
    
```

```


### graylog
    
```
(Image:("*\\\\update.exe") AND CommandLine:("*\\-\\-processStart*.exe*" "*\xe2\x80\x93createShortcut*.exe*"))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\update\\.exe))(?=.*(?:.*.*--processStart.*\\.exe.*|.*.*\xe2\x80\x93createShortcut.*\\.exe.*)))'
```



