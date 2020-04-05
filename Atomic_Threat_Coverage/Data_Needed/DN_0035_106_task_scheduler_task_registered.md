| Title              | DN_0035_106_task_scheduler_task_registered       |
|:-------------------|:------------------|
| **Description**    | General Windows Task Registration |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc774938(v=ws.10)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc774938(v=ws.10))</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-TaskScheduler/Operational     |
| **Provider**       | Microsoft-Windows-TaskScheduler    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>TaskName</li><li>UserContext</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
      <Provider Name="Microsoft-Windows-TaskScheduler" Guid="{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}" /> 
      <EventID>106</EventID> 
      <Version>0</Version> 
      <Level>4</Level> 
      <Task>106</Task> 
      <Opcode>0</Opcode> 
      <Keywords>0x8000000000000000</Keywords> 
      <TimeCreated SystemTime="2019-02-08T22:54:14.628673400Z" /> 
      <EventRecordID>5</EventRecordID> 
      <Correlation /> 
      <Execution ProcessID="908" ThreadID="2440" /> 
      <Channel>Microsoft-Windows-TaskScheduler/Operational</Channel> 
      <Computer>atc-win-10.atc.local</Computer> 
      <Security UserID="S-1-5-18" /> 
    </System>
  - <EventData Name="TaskRegisteredEvent">
      <Data Name="TaskName">\atctest</Data> 
      <Data Name="UserContext">atc-win-10.atc.local\user1</Data> 
    </EventData>
  </Event>

```




