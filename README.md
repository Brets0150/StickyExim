
# StickyExim
![](https://bretstaton.com/images/article_images/exim_attack/StickyEximLogo.png)

An Email HoneyPot
=============

## Features
- Easy to deploy.  The install scripts does all the work.
- Abuse report are atomaticlly created and sent to the attacking IP owner.
- Abuse reports are stored with a hash at time of creation incase needed later.

----
## Requirements

- Domain names.
	- One real domain you use for normal email. Example: myrealdomain.com
	- One domain for the HoneyPot(s). Example: myhoneydomain.com
- DNS record control.
	- Add a Wild card for all subdomains of  myhoneydomain.com to point to the IP of mail server for domain myrealdomain.com.
	In Bind this would look like "*.myhoneydomain.com.    IN      A       1.1.1.1."

- Another Mail Server
	- Anything will work. You can just use your normal email server; there is no special requirements. This is just to receive emails at.
	- Make "myhoneydomain.com" and "log.myhoneydomain.com" Domain Alias for "myrealdomain.com"
	- Create the account "abuse@myrealdomain.com".

- Debain 9
	- May work with other Debain version, but all testing was done in version 9.
----
### Install
---
```shell
apt update ; apt install -y git
git clone https://github.com/Brets0150/StickyExim.git
cd ./SticktyExim/
chmod +x *.sh
./install_StickyExim.sh <DomainNameUsedForHoneyPot> <ExternalEmailAddressToSendTestEmailTo>
```
##### Example:

```shell
./install_StickyExim.sh  "definitelynotahoneypot.com" "me@myreal-email.com"
```

After the install, a test email will be sent to the email address you provided above. If you do not get a email, check the mail log(/var/log/exim4/maillog).

----
### Configure
```shell
nano honey_harvester_exim_cve-2019-10149.sh
```
You need to find and update two variable at the top of this script.

This is the email that will appear on abuse reports that are sent. So this needs to be a valid email address. You may be contacted back by the people who get these reports.

Example: abuse@mydomainname.com
str_my_abuse_email_address_to_use_in_from_field=''

This email address must be different from the "str_my_abuse_email_address_to_use_in_from_field". This email is use to send a copy of a abuse reports to you so you are aware that an attack was found. Since the "str_my_abuse_email_address_to_use_in_from_field" domain will be local to this honeypot system, it will not try to send to a remote. I suggest adding a subdomain.

Example: abuse@log.mydomainname.com
str_my_abuse_email_address_to_send_copy_of_abuse_report=''

----

###Testing

If you want to test to confirm the honeypot is working, you can use this other project I found.
https://github.com/cowbe0x004/eximrce-CVE-2019-10149

NOTE: This will send a abuse report to the owner of the IP you are testing from(ie, your ISP). Use at your own risk.
----

###Happy Hunting!
