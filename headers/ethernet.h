#define	ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN];	/* destination host address */
	u_char ether_shost[ETHER_ADDR_LEN];	/* source host address */
	u_short ether_type;	/* IP? ARP? RARP? etc */
};
