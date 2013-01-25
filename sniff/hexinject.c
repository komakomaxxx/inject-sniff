/*
 * hexinject.c
 *
 *  Created on: 11/mag/2010
 *      Author: Acri Emanuele
 */

#include "hexinject.h"
#include "hexstring.h"
#include "hexdump.h"
#include "argparser.h"
#include "prettypacket.h"
#include <netinet/in.h>
#include  <sys/types.h>
#include  <sys/socket.h>

//デバックモード解除するときは下のdefine文をコメントアウト
//#define DEBUG 

#define PACKCK
#define HEADERSIZE 57
#define SEQUENCESIZE 4 
#define CRC32SIZE 2
#define LISTSIZE 10

/*
 * CRC
 */
static uint32_t CRC32[256] = {
    0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc,
    0x17c56b6b, 0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f,
    0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a,
    0x384fbdbd, 0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
    0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8,
    0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
    0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e,
    0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
    0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84,
    0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027,
    0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022,
    0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
    0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077,
    0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c,
    0x2e003dc5, 0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1,
    0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
    0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb,
    0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
    0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d,
    0x40d816ba, 0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
    0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f,
    0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044,
    0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689,
    0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
    0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683,
    0xd1799b34, 0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59,
    0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c,
    0x774bb0eb, 0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
    0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e,
    0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
    0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48,
    0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
    0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2,
    0xe6ea3d65, 0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601,
    0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604,
    0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
    0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6,
    0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad,
    0x81b02d74, 0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7,
    0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
    0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd,
    0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
    0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b,
    0x0fdc1bec, 0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
    0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679,
    0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12,
    0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af,
    0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
    0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5,
    0x9e7d9662, 0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06,
    0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03,
    0xb1f740b4
};
 
uint32_t calculateCRC32t(char* data, int length)
{
    uint32_t crc = 0xFFFFFFFF;
    while ( length-- > 0 ) {
        crc = (crc<<8) ^ CRC32[((crc>>24) ^ (uint32_t)(*data++)) & 0xFF];
    }
    return crc;
}

/*
 * Checksum IP
 */
uint16_t ip_cksum (uint16_t *buff, size_t len) {
    
    uint32_t sum = 0;
    uint16_t answer = 0;

    while(len > 1) {
        sum += *buff++;
        len -= 2;
    }

    if (len) {
        sum += * (uint8_t *) buff;
    }

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    answer = ~sum;

    return(answer);
}

/*
 * Checksum TCP
 */
uint16_t tcp_cksum(uint16_t *src_addr, uint16_t *dest_addr, uint16_t *buff, uint16_t len) {

    uint32_t sum = 0;
    uint16_t answer = 0;

    sum += src_addr[0];
    sum += src_addr[1];
    
    sum += dest_addr[0];
    sum += dest_addr[1];

    sum += htons(0x6);

    sum += htons(len);

    while(len > 1) {
        sum += *buff++;
        len -= 2;
    }

    if (len) {
        sum += * (uint8_t *) buff;
    }

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    answer = ~sum;

    return(answer);
}

/*
 * Checksum UDP
 */
uint16_t udp_cksum(uint16_t *src_addr, uint16_t *dest_addr, uint16_t *buff, size_t len) {
   
    uint32_t sum = 0;
    uint16_t answer = 0;
    
    sum += src_addr[0];
    sum += src_addr[1];
    
    sum += dest_addr[0];
    sum += dest_addr[1];

    sum += htons(0x11);

    sum += htons(len);

    while(len > 1) {
        sum += *buff++;
        len -= 2;
    }

    if (len) {
        sum += * (uint8_t *) buff;
    }

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    answer = ~sum;

    return(answer);
}

/*
 * Do checksum (if the packet requires it...)
 */
void do_crc32 (char *raw, size_t size) {
    uint16_t *crc = NULL;
    crc = (uint16_t *) &raw[size - (SEQUENCESIZE+CRC32SIZE)];
    *crc = 0;

    *crc = calculateCRC32t(raw+HEADERSIZE, size -(HEADERSIZE+ SEQUENCESIZE+CRC32SIZE));
}
int packetCk(uint16_t inpack){
    
    static uint16_t list[LISTSIZE];
    static uint32_t p=0;
    uint32_t i,cnt;

    cnt =p;
    for(i=0;i<LISTSIZE;i++){
	if(list[cnt] == inpack){
	    return 0;
	}
	cnt = (cnt -1+LISTSIZE)%LISTSIZE;
    }
    list[cnt]=inpack;
    p=(cnt+1)%LISTSIZE;

    return 1;
}
void do_cksum (char *raw, size_t size) {
    
    uint16_t *cksum = NULL;

    // disabled?
    if (options.no_cksum) {
        return;
    }

    // is ip?
    if ( size >= 34 && raw[12]==0x08  && raw[13]==0x00  ) {
       
        // ip checksum
        cksum = (uint16_t *) &raw[24];
        *cksum = 0;

        *cksum = ip_cksum((uint16_t *) &raw[14], 20);

        // next protocol
        switch(raw[23]) {

            // tcp
            case 0x06:
                if (size < 54) return; // size check
                cksum = (uint16_t *) &raw[50];
                *cksum = 0;
                *cksum = tcp_cksum((uint16_t *) &raw[26], (uint16_t *) &raw[30], (uint16_t *) &raw[34], (size-34));
                break;

            // udp
            case 0x11:
                if (size < 42) return; // size check
                cksum = (uint16_t *) &raw[40];
                *cksum = 0;
                *cksum = udp_cksum((uint16_t *) &raw[26], (uint16_t *) &raw[30], (uint16_t *) &raw[34], (size-34));
                break;

            // icmp
            case 0x01:
                if (size < 42) return; // size check
                cksum = (uint16_t *) &raw[36];
                *cksum = 0;
                *cksum = ip_cksum((uint16_t *) &raw[34], (size-34));
                break;
        }
    }
}

/*
 * Adjust packet size fields (if the packet requires it...)
 */
void do_size (char *raw, size_t size) {
    
    uint16_t *len_field = NULL;

    // disabled?
    if (options.no_size) {
        return;
    }

    // is ip?
    if ( size >= 34 && raw[12]==0x08  && raw[13]==0x00  ) {
       
        // ip total length
        len_field = (uint16_t *) &raw[16];

        *len_field = size - 14; // size - ethernet header
        *len_field = htons(*len_field);

        // next protocol
        switch(raw[23]) {

            // tcp
            case 0x06:
                if (size < 54) return; // size check
                // tcp uses header length field
                break;

            // udp
            case 0x11:
                if (size < 42) return; // size check
                len_field = (uint16_t *) &raw[38];
                *len_field = size - 14 - ((raw[14] & 0xF) * 4); // size - ethernet header - ip header
                *len_field = htons(*len_field);
                break;

            // icmp
            case 0x01:
                if (size < 42) return; // size check
                // no size field
                break;
        }
    }
}

/*
 * Inject a raw buffer to the network
 */
int inject_raw(pcap_t *fp, char *raw, size_t size) {

	assert(fp != NULL);
	assert(raw != NULL);

	int err = 0;
    
    /* packet size (if enabled) */
    do_size (raw, size);

    /* checksum */
    do_cksum (raw, size);

    do_crc32(raw,size);

	/* Send down the packet */
	err = pcap_sendpacket(fp, (unsigned char *) raw, size);

	return err;
}

/*
 * Inject an hexstring to the network
 */
int inject_hexstr(pcap_t *fp, char *hexstr) {

	assert(fp != NULL);
	assert(hexstr != NULL);

	int err = 0;
	int size = 0;
	char *raw = NULL;

	raw = hexstr_to_raw(hexstr, &size);

	/* Send down the packet */
	err = inject_raw(fp, raw, size);

	free(raw);

	return err;
}

/*
 * Sniff a packet from the network. Hexstring mode.
 */
char *sniff_hexstr(pcap_t *fp) {

	assert(fp != NULL);

	struct pcap_pkthdr hdr;
	char *hexstr = NULL;
	char *raw    = NULL;

	/* Sniff the packet */
	raw = (char *) pcap_next(fp, &hdr);

    if(raw == NULL)
    	return NULL;

    hexstr = raw_to_hexstr(raw, hdr.len);

    return hexstr;
}

/*
 * Sniff a packet from the network. Raw mode.
 */
char *sniff_raw(pcap_t *fp, size_t *size) {

	assert(fp != NULL);
	assert(size != NULL);

	struct pcap_pkthdr hdr;
	char *raw = NULL;

	/* Sniff the packet */
#ifndef DEBUG
	pcap_setdirection(fp, PCAP_D_IN);
#endif
	raw = (char *) pcap_next(fp, &hdr);

	*size = hdr.len;

    return raw;
}

/*
 * Convert standard input in hexstring format to raw format
 */
int convert_to_raw_loop()
{
    char buffer[BUFFER_SIZE];
    
    while (!feof(stdin)) {
    
        /* Read hexstring */
        if( !fgets(buffer, BUFFER_SIZE, stdin) ) {
            continue;
        }

        /* Write raw output */
    	int size = 0;
    	char *raw = NULL;

    	raw = hexstr_to_raw(buffer, &size);

    	fwrite(raw, 1, size, stdout);
        fflush(stdout);

    	free(raw);
    }

    return 0;
}

/*
 * Convert standard input in raw format to hexstring format
 */
int convert_to_hexstr_loop()
{
    char buffer[BUFFER_SIZE];
    int size;
    
    while (!feof(stdin)) {
        
        /* Read raw */
        size = fread(buffer, 1, BUFFER_SIZE, stdin);

        /* Write hexstring output */
        char *hexstr = raw_to_hexstr(buffer, size);
        
        fprintf(stdout, "%s\n", hexstr);
        fflush(stdout);

        free(hexstr);
    }

    return 0;
}

/*
 * Injection loop using hexstring format
 */
int inject_hexstr_loop(pcap_t *fp)
{
    char buffer[BUFFER_SIZE];

    while (!feof(stdin)) {

        /* Read hexstring */
        if( !fgets(buffer, BUFFER_SIZE, stdin) ) {
            continue;
        }

        /* Send down the packet */
        if (inject_hexstr(fp, buffer) != 0) {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
            return 1;
        }
    }

    return 0;
}

/*
 * Injection loop using raw format
 */
int inject_raw_loop(pcap_t *fp)
{
    char buffer[BUFFER_SIZE];
    size_t size;

    while (!feof(stdin)) {

        /* Read raw */
        size = fread(buffer, 1, BUFFER_SIZE, stdin);

        /* Send down the packet */
        if (inject_raw(fp, buffer, size) != 0) {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
            return 1;
        }
    }

    return 0;
}

/*
 * Sniffing loop with hexstring output
 */
int sniff_hexstr_loop(pcap_t *fp)
{
    char *hexstr;
    
    while ( 1 ) {

        /* Count */
        if (options.count_on) {
            if (options.count <= 0) {
                break;
            }
        }

        /* Sniff and print a packet */
        if ((hexstr = sniff_hexstr(fp))) {
            printf("%s\n", hexstr);
            fflush(stdout);
            free(hexstr);

            /* Count */
            if (options.count_on) {
                options.count--;
            }
        }

        usleep(options.sleep_time);
    }

    return 0;
}

/*
 * Sniffing loop with raw output
 */
int sniff_raw_loop(pcap_t *fp)
{
    char *packet;
    uint16_t * crc;
    size_t size;
    int cunt=0;

    while ( 1 ) {

        /* Count */
        if (options.count_on) {
            if (options.count <= 0) {
                break;
            }
        }

        size = BUFFER_SIZE;

        /* Sniff and print a packet */
        if ((packet = sniff_raw(fp, &size))) {
	    crc = packet + size-6;
//fprintf(stderr," crc==%d:%d\n",*crc,(uint16_t)calculateCRC32t(packet + HEADERSIZE,size - (HEADERSIZE + SEQUENCESIZE + CRC32SIZE)));
	    if (*crc != (uint16_t)calculateCRC32t(packet + HEADERSIZE,
		size - (HEADERSIZE + SEQUENCESIZE + CRC32SIZE))){
	    	fprintf(stderr,"CRC ERR\n");fflush(stderr);
		continue;
	    }
#ifdef PACKCK
	    if(packetCk(*crc) == 0){
		continue;
	    }
#endif

            fwrite(packet +HEADERSIZE-1, 1, size -( HEADERSIZE-1 +SEQUENCESIZE + CRC32SIZE) , stdout);
            fflush(stdout);

            /* Count */
            if (options.count_on) {
                options.count--;
            }
        }

        usleep(options.sleep_time);
    }

    return 0;
}

/*
 * Sniffing loop with raw outputi,
 * plus pretty printing of disassembled packet
 */
int sniff_raw_dis_loop(pcap_t *fp)
{
    char *packet;
    size_t size;

    while ( 1 ) {

        /* Count */
        if (options.count_on) {
            if (options.count <= 0) {
                break;
            }
        }

        size = BUFFER_SIZE;

        /* Sniff and print a packet */
        if ((packet = sniff_raw(fp, &size))) {
            ethernet_print(packet, size);
            
            /* Print end of packet */
            puts("\n ----------- ");
            fflush(stdout);

            /* Count */
            if (options.count_on) {
                options.count--;
            }
        }

        usleep(options.sleep_time);
    }

    return 0;
}

/*
 * Print disassembled example packet
 */
void print_dis_example_packet (enum packet_type type) {
    switch (type) {
        case tcp:  ethernet_print(tcp_packet, sizeof(tcp_packet)-1); break;
        case udp:  ethernet_print(udp_packet, sizeof(icmp_packet)-1); break;
        case icmp: ethernet_print(icmp_packet, sizeof(udp_packet)-1); break;
        case arp:  ethernet_print(arp_packet, sizeof(arp_packet)-1); break;
    }
    puts("");
}

/*
 * Main function
 */
int main(int argc, char **argv) {

    pcap_t *fp;
    struct bpf_program bpf;
    char errbuf[PCAP_ERRBUF_SIZE];

    int ret_val;

    char *dev;
	
    /* Parse cmdline options */
    parseopt(argc, argv);
    
    /* in case of conversion mode */
    if(options.convert_to_raw) {
        return convert_to_raw_loop();
    }
    else if(options.convert_to_hexstr) {
        return convert_to_hexstr_loop();
    }

    /* in case of prettyprinting a single disassembled packet  of example */
    if(options.print_dis_example != no_type) {
        print_dis_example_packet(options.print_dis_example);
        return 0;
    }
    
    /* find a device if not specified */
    if(!options.device) {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr,"Unable to find a network adapter: %s.\n", errbuf);
            return 1;
        }
    }
    else {
        dev = options.device;
    }

    /* Create packet capture handle */
    if((fp = pcap_create(dev, errbuf)) == NULL) {
        fprintf(stderr,"Unable to create pcap handle: %s\n", errbuf);
        return 1;
    }

    /* Set snapshot length */
    if(pcap_set_snaplen(fp, BUFSIZ) != 0) {
        fprintf(stderr,"Unable to set snapshot length: the interface may be already activated\n");
        return 1;
    }

    /* Set promiscuous mode */
    if(pcap_set_promisc(fp, options.promisc) != 0) {
        fprintf(stderr,"Unable to set promiscuous mode: the interface may be already activated\n");
        return 1;
    }

    /* Set read timeout */
    if(pcap_set_timeout(fp, 1000) != 0) { // a little patch i've seen in freebsd ports: thank you guys ;)
        fprintf(stderr,"Unable to set read timeout: the interface may be already activated\n");
        return 1;
    }

    /* Set monitor mode */
    if(options.monitor) {
        if(pcap_can_set_rfmon(fp)==0) {
            fprintf(stderr, "Monitor mode not supported by %s.\n", dev);
            return 1;
        }

        if((ret_val=pcap_set_rfmon(fp, 1)) != 0) {
            fprintf(stderr, "Unable to set monitor mode: the interface may be already activated.\n");
            return 1;
        }
    }

    /* Activate interface */
    if(pcap_activate(fp) != 0) {
        fprintf(stderr, "Unable to activate the interface: %s\n", pcap_geterr(fp));
        return 1;
    }
    
    /* Apply filter */
    if ( options.filter ) {

        if(pcap_compile(fp, &bpf, options.filter, 0, 0) != 0) {
            fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(fp));
            return 1;
        }

        if(pcap_setfilter(fp, &bpf) != 0) {
            fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(fp));
            return 1;
        }

    }

    /* Inject mode - Hexstring */
    if (options.inject && !options.raw) {
        ret_val = inject_hexstr_loop(fp);
    }
    
    /* Inject mode - Raw */
    else if (options.inject && options.raw) {
        ret_val = inject_raw_loop(fp);
    }
    
    /* Sniff mode - Hexstring */
    else if (options.sniff && !options.raw && !options.print_dis) {
        ret_val = sniff_hexstr_loop(fp);    
    }
    
    /* Sniff mode - Raw */
    else if (options.sniff && options.raw && !options.print_dis) {
        ret_val = sniff_raw_loop(fp);
    }

    /* Sniff mode - pretty printing, disassembling */
    else if (options.sniff && options.print_dis) {
        ret_val = sniff_raw_dis_loop(fp);
    }

    pcap_close(fp);

    return ret_val;
}
