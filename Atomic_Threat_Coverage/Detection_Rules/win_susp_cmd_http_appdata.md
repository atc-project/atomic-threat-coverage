| Title                | Command Line Execution with suspicious URL and AppData Strings                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1059: Command-Line Interface](https://attack.mitre.org/techniques/T1059)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1059: Command-Line Interface](../Triggers/T1059.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>High</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100](https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100)</li><li>[https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100](https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Command Line Execution with suspicious URL and AppData Strings
id: 1ac8666b-046f-4201-8aba-1951aaec03a3
status: experimental
description: Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs
    > powershell)
references:
    - https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100
    - https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100
author: Florian Roth
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - cmd.exe /c *http://*%AppData%
            - cmd.exe /c *https://*%AppData%
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - High
level: medium

```





### splunk
    
```
(CommandLine="cmd.exe /c *http://*%AppData%" OR CommandLine="cmd.exe /c *https://*%AppData%") | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Command Line Execution with suspicious URL and AppData Strings]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Command Line Execution with suspicious URL and AppData Strings status: experimental \
description: Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell) \
references: ['https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100', 'https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100'] \
tags: ['attack.execution', 'attack.t1059'] \
author: Florian Roth \
date:  \
falsepositives: ['High'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects a suspicious command line execution that includes an URL and AppData string in the command line parameters as used by several droppers (js/vbs > powershell)
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="cmd.exe /c *http://*%AppData%" OR CommandLine="cmd.exe /c *https://*%AppData%") | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Command_Line_Execution_with_suspicious_URL_and_AppData_Strings_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1059,level=medium"
```
