# Exploitation
In this challenge, we're launching a TCP SYN flooding on a targeted server causing a denial of service to any legitimate client trying to connect.


The idea behind the attack is to use spoofed ip addresses to send SYN packets to the server. The server, unaware of the attack, will respond to each connection attempt with a SYN-ACK packet and wait some time for the ACK which will never come (spoofed IP address baby).
During that time a new connection request will arrive thus leaving the server with an increasing amount of half-open connections. If no countermeasure is put in place, the server will run out of ressources and ultimately a legitimate client will be denied access. In worst case scenario, the server might even crash!


# Base code
First we're creating a raw ip socket following the TCP protocol and sendig a large number of packets to the target VM using multiple threads. Of course that was overkill, it took only one thread to completely flood the ports but hey! the more robots in a DDOS attack, the merrier  :D

# Analysis and statistics

Usig wireshark on our machine, we could see the ongoing SYN traffic, however, when we used tcpdump and netstat on the target VM, only a fraction of the packets sent seemed to reach the server- the poor thing already flooded, dah!


Using 
    netstat -n -p | grep SYN_REC | wc- l
we found that the number of half-open connections on the target VM saturated at 
    *10 for the echo server. 
    *128 for the web application
Of course, we couldn't access neither services when we tried connecting as a legitimate client.

Clarification : the target service was indeed down from the perspective of a legitimate client connecting to it, but the other application was up and running

Please note that we're flooding these ports because they're the only ones open on our VM target (yes we used nmap)

the command 
    netstat |grep SYN_RECV
actually shows the half open connections 
-see joined pictures

The next step was protecting the poor thing! Thus we tried making some changes to the /etc/sysctl.conf file :
-enabling the syncookies by uncommenting  
    net.ipv4.tcp_syncookies=1
-enabling spoofing protection by uncommenting
    net.ipv4.conf.defalut.rp_filter=1
    net.ipv4.conf.all.rp_filter=1
but for some reasons that didn't work??

Finally, we tried to increase the syn_rec limit by adding
    net.ipv4.tcp_max_syn_backlog=15
but again, nothing changed ?? 

of course now we understant that the limit depends on the port but what did we do wrong ? :'<

