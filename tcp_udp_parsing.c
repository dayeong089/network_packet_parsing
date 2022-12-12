#include<stdio.h>
#include<time.h>
#include<pcap.h>
#define MAX_P 50
	
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

    typedef struct tcp_header_{
        unsigned char source_port[2];
        unsigned char destination_port[2];
        unsigned char sequence[4];
        unsigned char ack[4];
        unsigned char hlen;
        unsigned char flag;
        unsigned char window[2];
		unsigned char checksum[2];
		unsigned char urgent[2];
    }tcp_header;

    typedef struct udp_header_{
        unsigned char source_port[2];
        unsigned char destination_port[2];
        unsigned char tot_Len[2];
        unsigned short checksum;
    }udp_header;

	typedef struct tcp_option_{
		unsigned char option[12];
	}tcp_option;

	typedef struct tcp_payload_{
		unsigned char payload[1];
	}tcp_payload;

	int total_size;
	int ip_length;
	int tcp_length;
	int max_tcp = 0;
	int max_udp = 0;
	
	unsigned char IP_Parsing(char *buffer) {
	    ip_header *ip = (ip_header *)buffer;

		//ip length
		int c = ip->tot_len[0];
	    int d = ip->tot_len[1];
	    ip_length = c*256 + d;
		printf("length in the IP header: %d\n", ip_length);

	    if(ip->protocol == 1)
	    {
	        printf("Protocol : ICMP");
	    }
	    else if(ip->protocol == 6)
	    {
	        printf("Protocol : TCP");
	    }
	    else if(ip->protocol == 17)
	    {
	        printf("Protocol : UDP");
	    }
	    else
	    {
	        printf("Protocol : %d",ip->protocol);
	    }

        return ip->protocol;
	}

    void TCP_Parsing(char *buffer) {
        tcp_header *tcp = (tcp_header*)buffer;
		tcp_length = ((tcp->hlen)/16)*4;
		int payload = total_size - 34 - tcp_length;
		if(payload > max_tcp)
		{
			max_tcp = payload;
		}

		//port number
        int a = tcp->source_port[0];
	    int b = tcp->source_port[1];
	    int source = a*256 + b;

		int c = tcp->destination_port[0];
	    int d = tcp->destination_port[1];
	    int destination = c*256 + d;

		printf("Source port : %d -> Destination port : %d\n",source,destination);

		//sequence number
		if(payload!=0)
		{
			int seq1 = tcp->sequence[0];
			int seq2 = tcp->sequence[1];
			int seq3 = tcp->sequence[2];
			int seq4 = tcp->sequence[3];
			unsigned int seq_value = seq1*256*256*256 + seq2*256*256 + seq3*256 + seq4;

			printf("Starting sequence number: %u, Ending sequence number: %u\n",seq_value,seq_value+payload-1);
		}
		else
		{
			int seq1 = tcp->sequence[0];
			int seq2 = tcp->sequence[1];
			int seq3 = tcp->sequence[2];
			int seq4 = tcp->sequence[3];
			unsigned int seq_value = seq1*256*256*256 + seq2*256*256 + seq3*256 + seq4;
			printf("Starting sequence number: %u\n",seq_value);
		}

		//acknowledgement number
		int ack1 = tcp->ack[0];
		int ack2 = tcp->ack[1];
		int ack3 = tcp->ack[2];
		int ack4 = tcp->ack[3];
		unsigned int ack_value = ack1*256*256*256 + ack2*256*256 + ack3*256 + ack4;
		printf("Acknowledgement number : %u\n",ack_value);

		//payload size
		printf("TCP payload size : %d bytes\n", payload);

		//window size
        int e = tcp->window[0];
	    int f = tcp->window[1];
	    int window = e*256 + f;
        printf("Advertising window size : %d\n", window);

		//segment type
		int flag_value = tcp->flag;
		int v1 = flag_value % 2; 
		int v2 = (flag_value/2) % 2;
		int v3 = (flag_value/4) % 2;
		int v4 = (flag_value/8) % 2;
		int v5 = (flag_value/16) % 2;
		int v6 = (flag_value/32) % 2;

		printf("TCP segment tyle : ");
		if(v1 == 1)
		{
			printf("F ");
		}
		if(v2 == 1)
		{
			printf("S ");
		}
		if(v3 == 1)
		{
			printf("R ");
		}
		if(v4 == 1)
		{
			printf("P ");
		}
		if(v5 == 1)
		{
			printf("A ");
		}
		if(v6 == 1)
		{
			printf("U ");
		}
		printf("\n");

		//tcp options
		int option_length = tcp_length - 20;
		if(tcp_length > 20)
		{
			tcp_option *opt = (tcp_option*)(buffer + sizeof(tcp_header));
			int now_length = 0;
			printf("All TCP options : ");
			while(1)
			{
				if(opt->option[now_length] == 0)
				{
					printf("EOL ");
					now_length += 1;
				}
				else if(opt->option[now_length] == 1)
				{
					printf("NOP ");
					now_length += 1;
				}
				else if(opt->option[now_length] == 2)
				{
					printf("MSS ");
					now_length += 4;
				}
				else if(opt->option[now_length] == 3)
				{
					printf("Window_scale ");
					now_length += 3;
				}
				else if(opt->option[now_length] == 4)
				{
					printf("SACK_permitted ");
					now_length += 2;
				}
				else if(opt->option[now_length] == 5)
				{
					printf("SACK_1-2 ");
					int sack_length = opt->option[now_length+1];
					now_length += sack_length;
				}

				if(now_length == option_length)
				{
					printf("\n");
					break;
				}
			}
		}
		
		//Application type
		if(source == 20 || destination == 20)
		{
			printf("Application type : FTP ");
		}
		if(source == 22 || destination == 22)
		{
			printf("Application type : SSH ");
		}
		if(source == 25 || destination == 25)
		{
			printf("Application type : SMTP ");
		}
		if(source == 37 || destination == 37)
		{
			printf("Application type : TIME ");
		}
		if(source == 53 || destination == 53)
		{
			printf("Application type : DNS ");
		}
		if(source == 80 || destination == 80)
		{
			printf("Application type : HTTP ");
		}
		if(source == 179 || destination == 179)
		{
			printf("Application type : BGP ");
		}
		if(source == 443 || destination == 443)
		{
			printf("Application type : HTTPS ");
		}
		printf("\n");
    }

    void UDP_Parsing(char *buffer) {
        udp_header *udp = (udp_header*)buffer;

		//port number
        int a = udp->source_port[0];
	    int b = udp->source_port[1];
	    int source = a*256 + b;

		int c = udp->destination_port[0];
	    int d = udp->destination_port[1];
	    int destination = c*256 + d;
		printf("Source port : %d -> Destination port : %d\n",source,destination);

		//payload size
		int e = udp->tot_Len[0];
		int f = udp->tot_Len[1];
		int length = e*256 + f - 8;
		printf("UDP payload size : %d bytes\n",length);

		if(length > max_udp)
		{
			max_udp = length;
		}

		if(source == 37 || destination == 37)
		{
			printf("Application type : TIME ");
		}
		if(source == 53 || destination == 53)
		{
			printf("Application type : DNS ");
		}
		if(source == 67 || destination == 67)
		{
			printf("Application type : BOOTP ");
		}
		if(source == 68 || destination == 68)
		{
			printf("Application type : BOOTP ");
		}
		if(source == 69 || destination == 69)
		{
			printf("Application type : TFTP ");
		}
		if(source == 80 || destination == 80)
		{
			printf("Application type : HTTP ");
		}
		if(source == 161 || destination == 161)
		{
			printf("Application type : SNMP ");
		}
		printf("\n");
    }
	
	p_header pheaders[1000];
	
	int main()
	{
	    f_header fh;
	    p_header *ph = pheaders;
	    char buffer[65536];
	    int pcount = 0;
	
	    //open file
	    FILE* fp = fopen("packet.pcap","rb");
	
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
	        strftime(buf, sizeof(buf), "%H:%M:%S", &ts);
	
	        //read packet header
	        pcount++;
	        printf("\n<Frame %d>\n", pcount);
	        printf("Local time that was recorded : ");
	        printf("%s", buf);
	        printf(".%d\n",ph->time.usec);
	        printf("captured length : %u bytes , actual length : %u bytes\n",  ph->caplen, ph->len);
			total_size = (int)ph->len;
	        fread(buffer, 1, ph->caplen, fp);
	
	        //parsing ethernet
	        ethernet *ph = (ethernet*)buffer;
	
	        //parsing ip
	        int type_num = ph->type;
            int protocol;
	        if (type_num == 8)
	        {
	            protocol = IP_Parsing(buffer + sizeof(ethernet));
	        }
	        ph++;
	        printf("\n");

            if(protocol == 6)
            {
                TCP_Parsing(buffer + sizeof(ethernet) + sizeof(ip_header));
            }

            else if(protocol == 17)
            {
                UDP_Parsing(buffer + sizeof(ethernet) + sizeof(ip_header));
            }
	    }

		printf("\nGreatest payload sizes among TCP segments : %d bytes\n",max_tcp);
		printf("Greatest payload sizes among UDP segments : %d bytes\n",max_udp);

	    fclose(fp);
	    return 0;
	}
