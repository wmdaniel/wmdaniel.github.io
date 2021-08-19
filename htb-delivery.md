# Delivery HTB Write up
# 2021

## Overview - Hack The Box: Delivery

### Disclaimer
The Hack the Box's ToC states `"Dont share how you hacked each machine with other members. This includes the invite code generation and all challenges."` This write up is intended as a practice exercise for ethical bounty disclosure and technical writing review. If this write up is found outside of my portfolio or re-hosted as a solutions key before the *delivery* box has been retired, please alert the page admin.

### Threat
The *root* login on the target is vulnerable and was exploited. This places all data stored on the server at critical risk, which has been confirmed. Additionally, any assets within the organization with similar user/passwords or root passwords is at risk.

### Summary
By accessing the delivery website and initiating a support ticket, full access to the Mattersmost database can be gained. There is a plaintext login and password stored in the Mattersmost management, which leads to FTP access of the user *maildeliverer*. A priveledge escalation exploit from this user can give full administrator access to all server files. This escalation is leveraged by locating a plain text password from a priveledged user in a log file. 

The CVSS for this exploit is:
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H`


### Methodology
The IP address given for the *delivery* box is `10.10.10.222`. 

The results of a basic network scan yielded:
```
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http    nginx 1.14.2
8065/tcp open  unknown
```
No relavant information was revealed by a `whatweb` or `dirbuster` scan.

The website hosted at port 80 is *delivery.com*. By clicking on the **Helpdesk** link, a Support Center option is available. This is the first, unsecured system. The attacker can open a new ticket and provide fake credentials (emai and name). By doing so, this creates not only a ticket in the **Mattermost** system, but it also creates the `$ticketnumber@delivery.htb` email in the host's email system. 

The attacker can log into the the **View ticket** system with the originally supplied email and the ticket number. With the `$ticketnumber@delivery.htb` email, the attacker is able to go to the **Mattermost** page (`www.delivery.com:8065`) make a new account linked to the `delivery.htb` url by providing the `$ticketnumber@delivery.htb` as the main email.

Logging into the **View ticket** system again will allow the attacker to see the successful registration conformation link and activate the **Mattermost** account.

In the **Mattermost** system, the attacker is able to see a note from the administrator stating the ssh login for the server is `maildeliverer:Youve_G0t_Mail!` With this information, the attacker has basic credentials. There is also the note from the root user:
```
Also please create a program to help us stop re-using the same passwords everywhere... Especially those that are a variant of "PleaseSubscribe!"
PleaseSubscribe! may not be in RockYou but if any hacker manages to get our hashes, they can use hashcat rules to easily crack all variations of common words or phrases.
```


__Reference 1__ shows all of the registered users and their respective permission groups. The `mysql` and `mattermost` users are the most likely targets for misconfiguration. With a simple search (__Reference 2__), the attacker is able to find the `/opt/mattermost/config/config.json` file, which inclues credentials for the mysql user `mmuser:Crack_The_MM_Admin_PW`.

Next, logging into the mysql database `mysql -u mmuser -D mattermost -p` and passing it the password above, the attacker is able to dump all hashed passwords for the Mattermost database (__Reference 3__). With this information and the note left by the `root` user in the **Mattermost** GUI, we can attack the hash with hashcat to find the password with a wordlist build around `PleaseSubscribe!`. This results in the `root:PleaseSubscribe!21` password.

### Suggested Resolution 

- Remove the usernames and passwords listed in the Mattermost GUI
- Do not auto-generate a local-domain email when creating a help ticket as a guest
- Require ssh-key login to the server
- Remove the plain-text username and password from the config.json file.
- Restrict hashed password access from the mmuser mysql account.


### References

#### Reference 1
```
maildeliverer@Delivery:/etc$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
avahi:x:106:115:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:107:116::/var/lib/saned:/usr/sbin/nologin
colord:x:108:117:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:109:7:HPLIP system user,,,:/var/run/hplip:/bin/false
maildeliverer:x:1000:1000:MailDeliverer,,,:/home/maildeliverer:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:110:118:MySQL Server,,,:/nonexistent:/bin/false
mattermost:x:998:998::/home/mattermost:/bin/sh
```
#### Reference 2
```
maildeliverer@Delivery:/opt/mattermost/config$ find / -type d -name "mattermost" -print 2>/dev/null
/opt/mattermost
/var/lib/mysql/mattermost
```
#### Reference 3
```
SHOW TABLES;
+------------------------+
| Tables_in_mattermost   |
+------------------------+
| Audits                 |
| Bots                   |
| ChannelMemberHistory   |
| ChannelMembers         |
| Channels               |
| ClusterDiscovery       |
| CommandWebhooks        |
| Commands               |
| Compliances            |
| Emoji                  |
| FileInfo               |
| GroupChannels          |
| GroupMembers           |
| GroupTeams             |
| IncomingWebhooks       |
| Jobs                   |
| Licenses               |
| LinkMetadata           |
| OAuthAccessData        |
| OAuthApps              |
| OAuthAuthData          |
| OutgoingWebhooks       |
| PluginKeyValueStore    |
| Posts                  |
| Preferences            |
| ProductNoticeViewState |
| PublicChannels         |
| Reactions              |
| Roles                  |
| Schemes                |
| Sessions               |
| SidebarCategories      |
| SidebarChannels        |
| Status                 |
| Systems                |
| TeamMembers            |
| Teams                  |
| TermsOfService         |
| ThreadMemberships      |
| Threads                |
| Tokens                 |
| UploadSessions         |
| UserAccessTokens       |
| UserGroups             |
| UserTermsOfService     |
| Users                  |
+------------------------+

SELECT Username, Password FROM Users;

+----------------------------------+--------------------------------------------------------------+
| Username                         | Password                                                     |
+----------------------------------+--------------------------------------------------------------+
| surveybot                        |                                                              |
| c3ecacacc7b94f909d04dbfd308a9b93 | $2a$10$u5815SIBe2Fq1FZlv9S8I.VjU3zeSPBrIEg9wvpiLaS7ImuiItEiK |
| 5b785171bfb34762a933e127630c4860 | $2a$10$3m0quqyvCE8Z/R1gFcCOWO6tEj6FtqtBn8fRAXQXmaKmg.HDGpS/G |
| root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
| test                             | $2a$10$YCgSpsEVZyCOoKfoOT7AN.Rf8f.JozKIS84x4D1zYsb.w0m7NdsNi |
| ff0a21fc6fc2488195e16ea854c963ee | $2a$10$RnJsISTLc9W3iUcUggl1KOG9vqADED24CQcQ8zvUm1Ir9pxS.Pduq |
| user                             | $2a$10$Z7dGMIYCbv5Kz6syMZ6v6eWgI7LkPixqW9X/qiN2ew.3P435uohDa |
| channelexport                    |                                                              |
| 9ecfb4be145d47fda0724f697f35ffaf | $2a$10$s.cLPSjAVgawGOJwB7vrqenPg2lrDtOECRtjwWahOzHfq1CoFyFqm |
| admin                            | $2a$10$IUl7EUnL6OhbVHic0kLv/eLydJPuXWJYotPi/CABeLJ8/UhbX.Mla |
+----------------------------------+--------------------------------------------------------------+
```
#### Reference 4
```
hashcat -m 3200 -r 0 passwd wordlist
```
