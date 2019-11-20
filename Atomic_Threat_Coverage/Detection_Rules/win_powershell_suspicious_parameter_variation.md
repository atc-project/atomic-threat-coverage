| Title                | Suspicious PowerShell Parameter Substring                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious PowerShell invocation with a parameter substring                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Penetration tests</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier](http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier)</li></ul>  |
| Author               | Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix) |


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
author: Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix)
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





### splunk
    
```
((Image="*\\\\Powershell.exe") (CommandLine=" -windowstyle h " OR CommandLine=" -windowstyl h" OR CommandLine=" -windowsty h" OR CommandLine=" -windowst h" OR CommandLine=" -windows h" OR CommandLine=" -windo h" OR CommandLine=" -wind h" OR CommandLine=" -win h" OR CommandLine=" -wi h" OR CommandLine=" -win h " OR CommandLine=" -win hi " OR CommandLine=" -win hid " OR CommandLine=" -win hidd " OR CommandLine=" -win hidde " OR CommandLine=" -NoPr " OR CommandLine=" -NoPro " OR CommandLine=" -NoProf " OR CommandLine=" -NoProfi " OR CommandLine=" -NoProfil " OR CommandLine=" -nonin " OR CommandLine=" -nonint " OR CommandLine=" -noninte " OR CommandLine=" -noninter " OR CommandLine=" -nonintera " OR CommandLine=" -noninterac " OR CommandLine=" -noninteract " OR CommandLine=" -noninteracti " OR CommandLine=" -noninteractiv " OR CommandLine=" -ec " OR CommandLine=" -encodedComman " OR CommandLine=" -encodedComma " OR CommandLine=" -encodedComm " OR CommandLine=" -encodedCom " OR CommandLine=" -encodedCo " OR CommandLine=" -encodedC " OR CommandLine=" -encoded " OR CommandLine=" -encode " OR CommandLine=" -encod " OR CommandLine=" -enco " OR CommandLine=" -en "))
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Suspicious PowerShell Parameter Substring]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Suspicious PowerShell Parameter Substring status: experimental \
description: Detects suspicious PowerShell invocation with a parameter substring \
references: ['http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier'] \
tags: ['attack.execution', 'attack.t1086'] \
author: Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix) \
date:  \
falsepositives: ['Penetration tests'] \
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
description = Detects suspicious PowerShell invocation with a parameter substring
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((Image="*\\Powershell.exe") (CommandLine=" -windowstyle h " OR CommandLine=" -windowstyl h" OR CommandLine=" -windowsty h" OR CommandLine=" -windowst h" OR CommandLine=" -windows h" OR CommandLine=" -windo h" OR CommandLine=" -wind h" OR CommandLine=" -win h" OR CommandLine=" -wi h" OR CommandLine=" -win h " OR CommandLine=" -win hi " OR CommandLine=" -win hid " OR CommandLine=" -win hidd " OR CommandLine=" -win hidde " OR CommandLine=" -NoPr " OR CommandLine=" -NoPro " OR CommandLine=" -NoProf " OR CommandLine=" -NoProfi " OR CommandLine=" -NoProfil " OR CommandLine=" -nonin " OR CommandLine=" -nonint " OR CommandLine=" -noninte " OR CommandLine=" -noninter " OR CommandLine=" -nonintera " OR CommandLine=" -noninterac " OR CommandLine=" -noninteract " OR CommandLine=" -noninteracti " OR CommandLine=" -noninteractiv " OR CommandLine=" -ec " OR CommandLine=" -encodedComman " OR CommandLine=" -encodedComma " OR CommandLine=" -encodedComm " OR CommandLine=" -encodedCom " OR CommandLine=" -encodedCo " OR CommandLine=" -encodedC " OR CommandLine=" -encoded " OR CommandLine=" -encode " OR CommandLine=" -encod " OR CommandLine=" -enco " OR CommandLine=" -en ")) | stats values(*) AS * by _time | search NOT [| inputlookup Suspicious_PowerShell_Parameter_Substring_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.execution,sigma_tag=attack.t1086,level=high"
```
