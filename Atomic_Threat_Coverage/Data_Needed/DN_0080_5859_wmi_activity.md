| Title              | DN_0080_5859_wmi_activity       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | WMI Event which provide ability to catch Timer-based WMI Events and provide  usefult information for identification of suspicious WMI activity |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity](https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity)</li><li>[https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-WMI-Activity/Operational     |
| **Provider**       | Microsoft-Windows-WMI-Activity    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>NamespaceName</li><li>Query</li><li>ProcessID</li><li>Provider</li><li>queryid</li><li>PossibleCause</li><li>CorrelationActivityID</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
      <Provider Name="Microsoft-Windows-WMI-Activity" Guid="{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}" /> 
      <EventID>5859</EventID> 
      <Version>0</Version> 
      <Level>0</Level> 
      <Task>0</Task> 
      <Opcode>0</Opcode> 
      <Keywords>0x4000000000000000</Keywords> 
      <TimeCreated SystemTime="2019-02-08T09:37:37.108925700Z" /> 
      <EventRecordID>57003</EventRecordID> 
      <Correlation ActivityID="{10490123-32E3-0000-B1F0-46D991BFD401}" /> 
      <Execution ProcessID="436" ThreadID="3076" /> 
      <Channel>Microsoft-Windows-WMI-Activity/Operational</Channel> 
      <Computer>atc-win-10.atc.local</Computer> 
      <Security UserID="S-1-5-18" /> 
    </System>
  - <UserData>
    - <Operation_EssStarted xmlns="http://manifests.microsoft.com/win/2006/windows/WMI">
        <NamespaceName>//./root/cimv2</NamespaceName> 
        <Query>select * from MSFT_SCMEventLogEvent</Query> 
        <User>S-1-5-32-544</User> 
        <Processid>436</Processid> 
        <Provider>SCM Event Provider</Provider> 
        <queryid>0</queryid> 
        <PossibleCause>Permanent</PossibleCause> 
      </Operation_EssStarted>
    </UserData>
  </Event>

```




