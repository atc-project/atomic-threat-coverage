| Title              | DN0095_linux_auth_pam_log       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Linux Pluggable Authentication Modules (PAM) authentication log |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[http://manpages.ubuntu.com/manpages/trusty/en/man7/pam.7.html](http://manpages.ubuntu.com/manpages/trusty/en/man7/pam.7.html)</li></ul> |
| **Platform**       | Linux    |
| **Type**           | auth        |
| **Channel**        | auth.log     |
| **Provider**       | pam    |
| **Fields**         | <ul><li>Hostname</li><li>UserName</li><li>Daemon</li><li>Message</li><li>pam_service</li><li>pam_user</li><li>pam_unix</li><li>pam_tty</li><li>pam_ruser</li><li>pam_rhost</li><li>pam_type</li><li>pam_authtok</li><li>pam_message</li><li>uid</li><li>logname</li><li>uid</li><li>euid</li><li>tty</li><li>ruser</li><li>rhost</li></ul> |


## Log Samples

### Raw Log

```
May 18 16:41:20 hostname service: (pam_unix) authentication failure; logname= uid=33 euid=33 tty= ruser= rhost= user=root

```




