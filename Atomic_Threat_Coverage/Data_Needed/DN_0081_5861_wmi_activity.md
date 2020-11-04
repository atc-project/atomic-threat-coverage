| Title              | DN_0081_5861_wmi_activity       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | WMI Event which provide ability to catch Timer-based WMI Events and provide  usefult information for identification of suspicious WMI activity |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity](https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity)</li><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-WMI-Activity/Operational     |
| **Provider**       | Microsoft-Windows-WMI-Activity    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>Namespace</li><li>ESS</li><li>Consumer</li><li>PossibleCause</li><li>CreatorSID</li><li>EventNamespace</li><li>Query</li><li>QueryLanguage</li><li>EventFilter</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-WMI-Activity" Guid="{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}" /> 
    <EventID>5861</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>0</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x4000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-02-06T20:23:40.952921100Z" /> 
    <EventRecordID>56793</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="1416" ThreadID="2244" /> 
    <Channel>Microsoft-Windows-WMI-Activity/Operational</Channel> 
    <Computer>atc-win-10.atc.local</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <UserData>
    - <Operation_ESStoConsumerBinding xmlns="http://manifests.microsoft.com/win/2006/windows/WMI">
      <Namespace>//./ROOT/Subscription</Namespace> 
      <ESS>SCM Event Log Filter</ESS> 
      <CONSUMER>NTEventLogEventConsumer="SCM Event Log Consumer"</CONSUMER> 
      <PossibleCause>Binding EventFilter: instance of __EventFilter { CreatorSID = {1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0}; EventNamespace = "root\\cimv2"; Name = "SCM Event Log Filter"; Query = "select * from MSFT_SCMEventLogEvent"; QueryLanguage = "WQL"; }; Perm. Consumer: instance of NTEventLogEventConsumer { Category = 0; CreatorSID = {1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0}; EventType = 1; Name = "SCM Event Log Consumer"; NameOfUserSIDProperty = "sid"; SourceName = "Service Control Manager"; };</PossibleCause> 
    </Operation_ESStoConsumerBinding>
  </UserData>
</Event>

```




