| Title              | DN_0037_4103_windows_powershell_executing_pipeline       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event records pipeline execution, including variable initialization and command command invocations. |
| **Logging Policy** | <ul><li>[LP0108_windows_powershell_module_logging](../Logging_Policies/LP0108_windows_powershell_module_logging.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/powershell/events/event-4103.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/powershell/events/event-4103.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-PowerShell/Operational     |
| **Provider**       | Microsoft-Windows-PowerShell    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>ContextInfo</li><li>UserData</li><li>Payload</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
        <Provider Name="Microsoft-Windows-PowerShell" Guid="{A0C1853B-5C40-4B15-8766-3CF1C58F985A}" /> 
        <EventID>4103</EventID> 
        <Version>1</Version> 
        <Level>4</Level> 
        <Task>106</Task> 
        <Opcode>20</Opcode> 
        <Keywords>0x0</Keywords> 
        <TimeCreated SystemTime="2019-02-05T15:05:16.564146000Z" /> 
        <EventRecordID>75824</EventRecordID> 
        <Correlation ActivityID="{3655DBA0-BD54-0000-AF51-563654BDD401}" /> 
        <Execution ProcessID="2588" ThreadID="4328" /> 
        <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
        <Computer>atc-win-10.atc.local</Computer> 
        <Security UserID="S-1-5-21-540864798-2899685673-3651185163-500" /> 
      </System>
    - <EventData>
        <Data Name="ContextInfo">Severity = Informational Host Name = ConsoleHost Host Version = 5.1.17134.407 Host ID = 3ff2018b-ab29-4049-a62d-851e5ca931ed Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Engine Version = 5.1.17134.407 Runspace ID = 52c750e1-1c34-4244-a6eb-feadfd70a959 Pipeline ID = 90 Command Name = New-CimInstance Command Type = Cmdlet Script Name = Command Path = Sequence Number = 329 User = atc-win-10\user1 Connected User = Shell ID = Microsoft.PowerShell</Data> 
        <Data Name="UserData" /> 
        <Data Name="Payload">CommandInvocation(New-CimInstance): "New-CimInstance" ParameterBinding(New-CimInstance): name="Namespace"; value="root/subscription" ParameterBinding(New-CimInstance): name="ClassName"; value="__EventFilter" ParameterBinding(New-CimInstance): name="Property"; value="System.Collections.Hashtable"</Data> 
      </EventData>
  </Event>

```




