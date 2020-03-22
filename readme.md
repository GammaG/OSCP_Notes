**OSCP Notes**

*NetDiscover*

find out the ip of the machine in the network

    netdiscover -i  eth1

*Find ports* 

*SSH fast UDP*
    nmap -Pn --top-ports 1000 -sU --stats-every 3m --max-retries 1 -T3 -oN /root/kioptrix.txt 192.168.156.102

    -sU                         UDP Scan

*SSH intensive* 
    nmap -Pn -sS --stats-every 3m --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit -T4 -p1-65535 -oN /root/desktop/kioptrix.txt 192.168.156.102

    -Pn                         Do not ping the host
    -sS                         Stealth Scan
    --stats-every 3m            Every 3 Min information should come back
    --max-retries 1             Only try once
    --max-scan-delay 20         nmap should wait a specific time - avoid rait limit
    --defeat-rst-ratelimit      don't send ack just send rst to much ack can trigger rait limit - for filtered ports
    -T4                         Intesitiy of 4
    -p1-65535                   scan all ports
    -oN <where to save it>      save the result to a specific file
    <target>                    ip e.g.

*Specific Ports Scan*
    sudo nmap -Pn -nvv -p 22,80,8080 --version intensity 9 -A -oN /home/kali/Desktop/kioptrix.txt

    -nvv 
    -Pn
    -p 22,80,111,139
    --version intensity 9 
    -A
    -oN /root/kioptrix1_detailed.txt
    <host>


*Search for Directories*

dirbuster - with UI
Good to download a wordlist from github
take a big one and remove "manual"

*analysis for vulnerabilities*

    nikto -h <ip> + port :80 or :443 

*SMB Enumeration*

    enum4linux -> 
        SMB Client 
        RPC Client
        NAT and MB Lookup

Has config bug
    locate smb.conf
    vim smb.conf

    under global add:
    client use spnego = no
    client ntlmv2 auth = no

enum4linux <ip>

find out SAMBA Version

    msfconsole
    search smb

search for an auxiliary scanner for smb with meatsploit

    use auxiliary/scanner/smb/smb_version
    put info - includes show options
    set rhost <ip>
    exploit
    --> gives you the version

    searchsploit samba 2.2
    see exploits compare them to exploit-db

    nbtscan <ip> - gives you basic info like NetBIOS Name

    smbclient -L <ip>

SAMBA is a good source for exploits

*DNS Enumeration*
