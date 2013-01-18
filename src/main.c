#define APPNAME		"qsniffer v0.3"
#define APPDESC		"a under developing simple eathernet sniffer"
#define APPCOPYRIGHT	"copyright (c) 2008 qnix <qnix[at]0x80[dot]org>"
#define APPDISCLAIMER	"there is absolutely no warranty for this program."

#include <stdio.h>
#include <pcap.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>

#include "ip.h"
#include "ethernet.h"
#include "tcp.h"

#define	ERROR		-1
#define	SNAP_LEN	1518
#define	SIZE_ETHERNET	14
#define	ETHER_ADDR_LEN 6

FILE *file;			// fd
char *filename;			// filename
int output = 0;			// output data to a file (0=disable,0!=enable)
int printtype = 0;		// 0 = offset/hex/ascii -- 1= offset/ascii

/* prototypes */
void
got_packet(u_char * args, const struct pcap_pkthdr *header,
	   const u_char * packet);

void print_payload(const u_char * payload, int len);
void print_hex_ascii_line(const u_char * payload, int len, int offset);
void print_ascii_line(const u_char * payload, int len, int offset);
void print_app_banner(void);
void print_app_usage(void);
void help(char *appname);
void termination_handler(int signum);

enum boole {
	FALSE,
	TRUE
};

/*
 * banner
 * */
void print_app_banner(void)
{
	fprintf(stdout,
		"************************************************************\n");
	fprintf(stdout, "%s - %s\n", APPNAME, APPDESC);
	fprintf(stdout, "%s\n", APPCOPYRIGHT);
	fprintf(stdout, "%s\n", APPDISCLAIMER);
	fprintf(stdout,
		"************************************************************\n\n");
}

/*
 * help
 **/
void help(char *appname)
{
	fprintf(stdout, "\nusage : %s\t-i <interface>\t\t: select a device\n"
		"\t\t\t-f <filter-expression>\t: select a filter (ex. tcp , ip , \"tcp port 80\"..etc) [default: all]\n"
		"\t\t\t-n <number-of-packets>\t: select the number of packets to capture [default: all]\n"
		"\t\t\t-o <output-filename>\t: select a filename for output\n"
		"\t\t\t-t <output-type>\t: 0 = [offset/hex/ascii]\n"
		"\t\t\t\t\t\t: 1 = [offset/ascii]\n"
		"\t\t\t-p\t\t\t: disable promisc mode [default: enable]\n"
		"\t\t\t-v\t\t\t: qsniffer version\n"
		"\t\t\t-h\t\t\t: help\n\n", APPNAME);
	exit(EXIT_FAILURE);
}

/*
 * print data in ascii
 * @input : payload, len, offset
 */
void print_ascii_line(const u_char * payload, int len, int offset)
{
	int i;
	const u_char *ch;

	fprintf(stdout, "%05d\t", offset);
	
        ch = payload;

	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			fprintf(stdout, "%c", *ch);
		else
			fprintf(stdout, ".");
		ch++;
	}

	fprintf(stdout, "\n");

}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   get / http/1.1..
 * @input : payload, len, offset
 */
void print_hex_ascii_line(const u_char * payload, int len, int offset)
{

	int i, gap;
	const u_char *ch;

	fprintf(stdout, "%05d", offset);
	if (output == 1)
		fprintf(file, "%05d", offset);

	ch = payload;
	for (i = 0; i < len; i++) {
		fprintf(stdout, "%02x ", *ch);
		if (output == 1)
			fprintf(file, "%02x", *ch);
		ch++;
		if (i == 7) {
			fprintf(stdout, " ");
			if (output == 1)
				fprintf(file, " ");
		}
	}
        if (len < 8) {
		fprintf(stdout, " ");
		if (output == 1)
			fprintf(file, " ");
	}
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			fprintf(stdout, "   ");
			if (output == 1)
				fprintf(file, "   ");
		}
	}
	fprintf(stdout, "   ");
	if (output == 1)
		fprintf(file, "   ");

	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch)) {
			fprintf(stdout, "%c", *ch);
			if (output == 1)
				fprintf(file, "%c", *ch);
		} else {
			fprintf(stdout, ".");
			if (output == 1)
				fprintf(file, ".");
		}
		ch++;
	}

	fprintf(stdout, "\n");
	if (output == 1)
		fprintf(file, "\n");
}

/*
 * print packet payload data (avoid printing binary data)
 * @input : payload, len
 */
void print_payload(const u_char * payload, int len)
{

	int len_rem = len, line_len;
	int line_width = 16;	/* bytes per line */
	int offset = 0;		/* zero base offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	if (printtype == 0) {
		if (len <= line_width) {
			print_hex_ascii_line(ch, len, offset);
			return;
		}
	}

	for (;;) {
		line_len = line_width % len_rem;
		if (printtype == 0)
			print_hex_ascii_line(ch, line_len, offset);
		else
			print_ascii_line(ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if (printtype == 0) {
			if (len_rem <= line_width) {
				print_hex_ascii_line(ch, len_rem, offset);
				break;
			}
		} else if (printtype == 1) {
			if (len_rem <= line_width) {
				print_ascii_line(ch, len_rem, offset);
				break;
			}
		}
	}
}

/*
 * print packet
 * @input args, packet header, packet
 */
void
got_packet(u_char * args, const struct pcap_pkthdr *header,
	   const u_char * packet)
{

	int count = 1;	// packet count

	/* packet headers */
	const struct sniff_ethernet *ethernet;	/* ethernet header */
	const struct sniff_ip *ip;	/* ip header */
	const struct sniff_tcp *tcp;	/* tcp header */
	const char *payload;	/* packet payload */

	int size_ip, size_tcp, size_payload;

	fprintf(stdout, "\npacket number %d:\n", count);
	if (output == 1)
		fprintf(file, "\npacket number %d:\n", count);
	count++;

	/* ethernet header */
	ethernet = (struct sniff_ethernet *)(packet);

	/* ip header offset */
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		fprintf(stdout, "   * invalid ip header length: %u bytes\n",
			size_ip);
		if (output == 1)
			fprintf(file,
				"   * invalid ip header length: %u bytes\n",
				size_ip);
		return;
	}

	/* src/dst ip  */
	fprintf(stdout, "       from: %s\n", inet_ntoa(ip->ip_src));
	if (output == 1)
		fprintf(file, "       from: %s\n", inet_ntoa(ip->ip_src));
	fprintf(stdout, "         to: %s\n", inet_ntoa(ip->ip_dst));
	if (output == 1)
		fprintf(file, "       to:%s\n", inet_ntoa(ip->ip_dst));

	/* ip protocol */
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		fprintf(stdout, "   protocol: tcp\n");
		if (output == 1)
			fprintf(file, "   protocol: tcp\n");
		break;
	case IPPROTO_UDP:
		fprintf(stdout, "   protocol: udp\n");
		if (output == 1)
			fprintf(file, "   protocol: udp\n");
		return;
	case IPPROTO_ICMP:
		fprintf(stdout, "   protocol: icmp\n");
		if (output == 1)
			fprintf(file, "   protocol: icmp\n");
		return;
	case IPPROTO_IP:
		fprintf(stdout, "   protocol: ip\n");
		if (output == 1)
			fprintf(file, "   protocol: ip\n");
		return;
	default:
		fprintf(stdout, "   protocol: unknown\n");
		if (output == 1)
			fprintf(file, "   protocol: unknown\n");
		return;
	}

        /* tcp packet */

	/* tcp header offset */
	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20) {
		fprintf(stdout, "   * invalid tcp header length: %u bytes\n",
			size_tcp);
		if (output == 1)
			fprintf(file,
				"   * invalid tcp header length: %u bytes\n",
				size_tcp);
		return;
	}

	fprintf(stdout, "   src port: %d\n", ntohs(tcp->th_sport));
	if (output == 1)
		fprintf(file, "   src port: %d\n", ntohs(tcp->th_sport));
	fprintf(stdout, "   dst port: %d\n", ntohs(tcp->th_dport));
	if (output == 1)
		fprintf(file, "   dst port: %d\n", ntohs(tcp->th_dport));

	/* tcp payload (segment) offset */
	payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

	/* tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/* payload data either string/binary */
        if (size_payload > 0) {
		fprintf(stdout, "   payload (%d bytes):\n", size_payload);
		if (output == 1)
			fprintf(file, "   payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}

	return;
}

/*
 * handler for signals
 * @input : signal number
 */
void termination_handler(int signum)
{
	fprintf(stderr, "\n*** qsniffer interrupted ***\n");
	if (output == 1) {
		fprintf(stderr, "*** saving %s ***\n", filename);
		fclose(file);
	}
	fprintf(stderr, "*** exiting... ***\n");
	exit(EXIT_FAILURE);
}

/*
 * main
 */
int main(int argc, char **argv)
{

	char *device = NULL;	// device name
	char *nets;		// dot notation address
	char *masks;		// dot notation mask
	char errbuf[PCAP_ERRBUF_SIZE];	// ERROR buffer
	char *filter_exp = NULL;	// filter expression
	pcap_t *handle;		// packet capture handler
	struct bpf_program fp;	// compiled filter
	bpf_u_int32 mask;	// subnet mask
	bpf_u_int32 net;	// ip
	struct in_addr addr;
	int num_packets = 0;	// packets to capture
	int c;			// getopt opt
	int promisc = 0;	// promisc (enable=0/disable=1)
	opterr = 0;		// getopt ERROR

	print_app_banner();

	// signal halding
	if (signal(SIGINT, termination_handler) == SIG_IGN)
		signal(SIGINT, SIG_IGN);
	if (signal(SIGHUP, termination_handler) == SIG_IGN)
		signal(SIGHUP, SIG_IGN);
	if (signal(SIGTERM, termination_handler) == SIG_IGN)
		signal(SIGTERM, SIG_IGN);

	while ((c = getopt(argc, argv, "o:t:n:i:f:hpv")) != -1) {
		switch (c) {
		case 'i':	// interface
			device = optarg;
			break;
		case 'h':	// help();
			help(argv[0]);
			break;
		case 'v':	// view print_app_banner();
			exit(EXIT_SUCCESS);
			break;
		case 'p':	// disable promisc mode
			promisc = 1;
			break;
		case 't':
			printtype = atoi(optarg);
			break;
		case 'f':	// filter expression
			filter_exp = optarg;
			break;
		case 'n':	// number of packets to capture
			num_packets = atoi(optarg);
			break;
		case 'o':	// log output to a file
			output = 1;	// enable output
			filename = optarg;	// set filename
			break;
		case '?':
			if (optopt == 't') {
				fprintf(stderr,
					"option -%c requires an argument.\n",
					optopt);
				help(argv[0]);
			} else if (optopt == 'i') {
				fprintf(stderr,
					"option -%c requires an argument.\n",
					optopt);
				help(argv[0]);
			} else if (optopt == 'f') {
				fprintf(stderr,
					"option -%c requires a filter expression.\n",
					optopt);
				help(argv[0]);
			} else if (optopt == 'n') {
				fprintf(stderr,
					"option -%c requires a packets number to capture.\n",
					optopt);
				help(argv[0]);
			} else if (optopt == 'o') {
				fprintf(stderr,
					"option -%c requires a file name.\n",
					optopt);
				help(argv[0]);
			} else if (isprint(optopt)) {
				fprintf(stderr, "unknown option `-%c'.\n",
					optopt);
				help(argv[0]);
			} else {
				fprintf(stderr,
					"unknown option character `\\x%x'.\n",
					optopt);
				help(argv[0]);
			}
		}
	}

	/* check if print type is available */
	if (printtype > 1) {
		fprintf(stderr,
			"the printing type you selected is not available\n");
		help(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* select device automatically or manually */
	if (device == NULL) {
		device = pcap_lookupdev(errbuf);
		fprintf(stdout, "for help type \"%s -h\"\n\n", argv[0]);
		fprintf(stdout, "[*device detection : auto*]\n");
	} else {
		fprintf(stdout, "[*device detection : manual*]\n");
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "couldn't get netmask for device %s\n", errbuf);
		net = 0;
		mask = 0;
		exit(EXIT_FAILURE);
	} else {

		addr.s_addr = net;
		nets = inet_ntoa(addr);

		if (nets == NULL) {
			perror("inet_ntoa");
			exit(EXIT_FAILURE);
		}

		fprintf(stdout, "net : %s\n", nets);

		addr.s_addr = mask;
		masks = inet_ntoa(addr);

		if (masks == NULL) {
			perror("inet_ntoa");
			exit(EXIT_FAILURE);
		}

		fprintf(stdout, "mask : %s\n", masks);
	}

	/* filename */
	if (output == 1)
		fprintf(stdout, "output filename : %s\n", filename);

	/* info */
	fprintf(stdout, "device : %s\n", device);
	if (num_packets == 0)
		fprintf(stdout, "number of packets : all\n");
	else
		fprintf(stdout, "number of packets : %d\n", num_packets);
	if (filter_exp == 0)
		fprintf(stdout, "filter expression : all\n");
	else
		fprintf(stdout, "filter expression : %s\n", filter_exp);
	if (promisc == 1)
		fprintf(stdout, "promisc mode : false\n");
	else
		fprintf(stdout, "promisc mode : true\n");
	if (printtype == 0)
		fprintf(stdout, "print type : all (offset,hex,asii)");
	else if (printtype == 1)
		fprintf(stdout, "print type : ascii (offset,acsii)");

	/* open capture device in default mode or promisc mode */
	if (promisc == 1) {
		handle = pcap_open_live(device, SNAP_LEN, FALSE, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "couldn't open device %s", errbuf);
			exit(EXIT_FAILURE);
		}
	} else {
		handle = pcap_open_live(device, SNAP_LEN, TRUE, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr,
				"couldn't open device %s in promisc mode\n",
				errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* make sure we're capturing on an ethernet device */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an ethernet\n", device);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, FALSE, net) == -1) {
		fprintf(stderr, "couldn't parse filter %s:%s\n", filter_exp,
			pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "couldn't install filter %s:%s\n", filter_exp,
			pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* output data to FILE */
	if (output == 1) {
		file = fopen(filename, "w+");	// open file
		if (file == NULL) {
			fprintf(stderr, "couldn't write on %s\n", filename);
			output = 0;	// disable
		} else {
			fprintf(file, "*** this file created by %s ***\n\n",
				APPNAME);
		}
	}

	/* set our callback function */
	if (num_packets != 0) {
		// specified number of packets to sniff
		pcap_loop(handle, num_packets, got_packet, NULL);
	} else {
		// unspecified number of packets to sniff
		pcap_loop(handle, -1, got_packet, NULL);
	}

	/* cleanup pcap */
	pcap_freecode(&fp);
	pcap_close(handle);

	/* if file open then fclose() */
	if (output == 1)
		fclose(file);

	fprintf(stdout, "\n[*capture complete*]\n");

	return 0;
}
