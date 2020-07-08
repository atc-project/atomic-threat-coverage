| Title              | DN0036_4104_windows_powershell_script_block       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event records script |
| **Logging Policy** | <ul><li>[LP0109_windows_powershell_script_block_logging](../Logging_Policies/LP0109_windows_powershell_script_block_logging.md)</li></ul> |
| **References**     | <ul><li>[https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/](https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/)</li><li>[https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/powershell/events/event-4104.md](https://github.com/Cyb3rWard0g/OSSEM/blob/master/data_dictionaries/windows/powershell/events/event-4104.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-PowerShell/Operational     |
| **Provider**       | Microsoft-Windows-PowerShell    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>MessageNumber</li><li>MessageTotal</li><li>ScriptBlockText</li><li>ScriptBlockId</li><li>Path</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
      <Provider Name="Microsoft-Windows-PowerShell" Guid="{A0C1853B-5C40-4B15-8766-3CF1C58F985A}" /> 
      <EventID>4104</EventID> 
      <Version>1</Version> 
      <Level>5</Level> 
      <Task>2</Task> 
      <Opcode>15</Opcode> 
      <Keywords>0x0</Keywords> 
      <TimeCreated SystemTime="2019-02-05T15:05:16.554318000Z" /> 
      <EventRecordID>75823</EventRecordID> 
      <Correlation ActivityID="{3655DBA0-BD54-0000-AE51-563654BDD401}" /> 
      <Execution ProcessID="2588" ThreadID="4328" /> 
      <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
      <Computer>atc-win-10.atc.local</Computer> 
      <Security UserID="S-1-5-21-540864798-2899685673-3651185163-500" /> 
    </System>
  - <EventData>
      <Data Name="MessageNumber">1</Data> 
      <Data Name="MessageTotal">1</Data> 
      <Data Name="ScriptBlockText">$FilterArgs = @{name='AtomicRedTeam-WMIPersistence-Example'; EventNameSpace='root\CimV2'; QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"}; $Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs $ConsumerArgs = @{name='AtomicRedTeam-WMIPersistence-Example'; CommandLineTemplate="$($Env:SystemRoot)\System32\notepad.exe";} $Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs $FilterToConsumerArgs = @{ Filter = [Ref] $Filter; Consumer = [Ref] $Consumer; } $FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs</Data> 
      <Data Name="ScriptBlockId">414c1110-3b57-40bf-9502-e45053cce9dd</Data> 
      <Data Name="Path" /> 
    </EventData>
  </Event>

```




