#include<stdio.h>
#include<time.h>
	
	typedef struct timeval_ {
	    int sec;
		int usec;	
	}timeval;
	
	typedef struct ethernet_ {
	    unsigned char mac_dst[6];
	    unsigned char mac_src[6];
	    unsigned short type;
	}ethernet;
	
	typedef struct f_header_{
	    int a_1;
	    int a_2;
	    int a_3;
	    int a_4;
	    int a_5;
	    int a_6;
	}f_header;
	
	typedef struct p_header_{
	    timeval time;
	    unsigned int caplen;
	    unsigned int len;
	}p_header;
	
	typedef struct ip_header_{
	    unsigned char hlen : 4;
	    unsigned char version : 4;
	    unsigned char service;
		unsigned char tot_len[2];
	    unsigned char id[2];
	    unsigned short flag;
	    unsigned char ttl;
	    unsigned char protocol;
	    unsigned short checksum;
	    unsigned char ip_src[4];
	    unsigned char ip_dst[4];
	}ip_header;
	
	void IP_Parsing(char *buffer) {
	    ip_header *ip = (ip_header *)buffer;

		//ip length
		printf("\nlength in the IP header: ");
		int c = ip->tot_len[0];
	    int d = ip->tot_len[1];
	    int length = c*256 + d;
		printf("%d",length);

	    //source & destination ip address
	    printf("\nSource IP address : ");
	    for(int i=0;i<3;i++)
	    {
	        printf("%d.", ip->ip_src[i]);
	    }
	    printf("%d",ip->ip_src[3]);
	    printf(" -> Destination IP address : ");
	    for(int i=0;i<3;i++)
	    {
	        printf("%d.", ip->ip_dst[i]);
	    }
	    printf("%d",ip->ip_dst[3]);
	    //protocol
	    if(ip->protocol == 1)
	    {
	        printf("\nProtocol : ICMP");
	    }
	    else if(ip->protocol == 6)
	    {
	        printf("\nProtocol : TCP");
	    }
	    else if(ip->protocol == 17)
	    {
	        printf("\nProtocol : UDP");
	    }
	    else
	    {
	        printf("\nProtocol : %d",ip->protocol);
	    }
	    //identification
	    printf("\nidentification : 0x");
	    for(int i=0; i<2; i++)
	    {
	        printf("%02x", ip->id[i]);
	    }
	    printf("\n");
	    //Flags
	    printf("Flag : 0x");
	    printf("%02x\n", ip->flag);
	    //identification in decimal
	    int a = ip->id[0];
	    int b = ip->id[1];
	    int ident = a*256 + b;
	    printf("identification in decimal : %d\n",ident);
	    //Flags in either DF or MF
	    if (ip->flag & 0x40)
	    {
	        printf("Flag : DF\n");
	    }
	    else if((ip->flag & 0x20) == 0)
	    {
	        printf("Flag : Last Fragment.\n");
	    }
	    else if((ip->flag & 0x00) == 0)
	    {
	        printf("Flag : MF\n");
	    }
	    //TTL
	    printf("TTL : %d\n", ip->ttl);
	}
	
	p_header pheaders[1000];
	
	int main()
	{
	    f_header fh;
	    p_header *ph = pheaders;
	    char buffer[65536];
	    int pcount = 0;
	
	    //open file
	    FILE* fp = fopen("packets.pcap","rb");
	
	    //ignore file header(24 bytes)
	    fread(&fh, sizeof(fh), 1, fp);
	
	    while(feof(fp) == 0)
	    {
	        if(fread(ph, sizeof(p_header),1,fp) != 1) { break; }

	        time_t     now;
	        struct tm  ts;
	        char       buf[80];
	        now = ph->time.sec;
	        ts = *localtime(&now);
	        strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S", &ts);
	
	        //read packet header
	        pcount++;
	        printf("Frame %d\n", pcount);
	        printf("Local time that was recorded : ");
	        printf("%s", buf);
	        printf(".%d\n",ph->time.usec);
	        printf("capture length : %u bytes , actual length : %u bytes\n",  ph->caplen, ph->len);
	
	        fread(buffer, 1, ph->caplen, fp);
	
	        //parsing ethernet
	        ethernet *ph = (ethernet*)buffer;
	        printf("Src MAC address : "); 
	        for (int i = 0; i < 5; i++) {
	            printf("%02x:", ph->mac_src[i]);
	        }
	        printf("%02x", ph->mac_src[5]);
	        printf(" -> ");
	        printf("Dst MAC address : "); 
	        for (int i = 0; i < 5; i++) {
	            printf("%02x:", ph->mac_dst[i]);
	        }
	        printf("%02x", ph->mac_dst[5]);
	
	        //parsing ip
	        int type_num = ph->type;
	        if (type_num == 8)
	        {
	            IP_Parsing(buffer + sizeof(ethernet));
	        }
	        ph++;
	        printf("\n");
	    }
	    fclose(fp);
	    return 0;
	}
