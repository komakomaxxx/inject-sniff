#ifndef __ARGPARSER_H__
#define __ARGPARSER_H__

#include <stdio.h>
#include <string.h>

#include <getopt.h>

#include "hexinject.h"

#define VERSION "1.4"

/*
 * Cmdline options
 */
struct {
    int inject;                    // inject mode
    int sniff;                     // sniff mode
    int raw;                       // raw mode
    char *device;                  // interface
    char *filter;                  // custom pcap filter
    int count;                     // number of packets to capture
    int count_on;                  // enable count
    int sleep_time;                // sleep time in microseconds
    int no_cksum;                  // disable packet checksum
    int no_size;                   // disable packet size
    int promisc;                   // promiscuous mode
    int monitor;                   // enable monitor mode
    int convert_to_hexstr;         // convert input to hexstr
    int convert_to_raw;            // convert input to raw
    int print_dis;                 // enable disassembling and pretty printing
    enum packet_type print_dis_example; // type of the example packet to pretty print
} options;

/*
 * Program usage template
 */
const char usage_template[] =
    "HexInject " VERSION " [hexadecimal packet injector/sniffer]\n"
    "written by: Emanuele Acri <crossbower@gmail.com>\n\n"
    "Usage:\n"
    "   hexinject <mode> <options>\n"
    "\nOptions:\n"
    "  -s sniff mode\n"
    "  -p inject mode\n"
    "  -r raw mode (instead of the default hexadecimal mode)\n"
    "  -i device: network device to use\n"
    "  -f filter: custom pcap filter\n"
    "  -c number of packets to capture\n"
    "  -t sleep time in microseconds (default 100)\n"
    "\nInjection options:\n"
    "  -C disable automatic packet checksum\n"
    "  -S disable automatic packet size\n"
    "\nInterface options:\n"
    "  -P disable promiscuous mode\n"
    "  -M put the wireless interface in monitor mode\n"
    "     (experimental: use airmon-ng instead...)\n"
    "\nConversion mode:\n"
    "  -x convert raw input to hexstring\n"
    "  -y convert hexstring input to raw\n"
    "\nPretty printing and disassembling options:\n"
    "  -D enable disassembling (pretty printing) of packets\n"
    "  -L pretty print an example packet\n"
    "     (requires packet type: tcp, udp, icmp or arp)\n"
    "\nOther options:\n"
    "  -h help screen\n";

/*
 * Program usage
 */
void usage(FILE *out, const char *error)
{
    fputs(usage_template, out);

    if(error)
        fputs(error, out);

    exit(1);
}

/*
 * Convert string to packet_type
 */
enum packet_type str_to_packet_type(const char *str)
{
    if (strcmp(str, "tcp") == 0)
        return tcp;
    if (strcmp(str, "udp") == 0)
        return udp;
    if (strcmp(str, "icmp") == 0)
        return icmp;
    if (strcmp(str, "arp") == 0)
        return arp;
    return no_type;
}

/*
 * Parser for command line options
 * See getopt(3)...
 */
int parseopt(int argc, char **argv)
{
    char *c=NULL, *x=NULL;
    char ch;
    
    // cleaning
    memset(&options, 0, sizeof(options));
    
    // default options
    options.sleep_time = 100;
    options.promisc    = 1;
    
    const char *shortopt = "spri:f:c:t:CSPMxyDL:h"; // short options
    
    while ((ch = getopt (argc, argv, shortopt)) != -1) {
        switch (ch) {
        
            case 's': // sniff mode
                options.sniff = 1;
                break;
            
            case 'p': // inject mode
                options.inject = 1;
                break;
                
            case 'r': // raw mode
                options.raw = 1;
                break;  
            
            case 'i': // interface
                options.device = optarg;
                break;
            
            case 'f': // custom filter
                options.filter = optarg;
                break;
                
            case 'c': // packet count
                options.count = atoi(optarg);
                options.count_on = 1;
                break;

            case 't': // sleep time in microseconds
                options.sleep_time = atoi(optarg);
                break;

            case 'C': // disable packet checksum
                options.no_cksum = 1;
                break;

            case 'S': // disable packet size
                options.no_size = 1;
                break;

            case 'P': // disable promiscuous mode
                options.promisc = 0;
                break;

            case 'M': // enable monitor mode
                options.monitor = 1;
                break;
                
            case 'x': // convert input to raw
                options.convert_to_hexstr = 1;
                break;
                
            case 'y': // convert input to hexstring
                options.convert_to_raw = 1;
                break;

            case 'D': // enable disassembling and pretty printing
                options.print_dis = 1;
                break;  
            
            case 'L': // pretty print a single example packet
                options.print_dis_example = str_to_packet_type(optarg);
                if (options.print_dis_example == no_type)
                    usage(stderr, "\nError: invalid type for option -L.\n");
                break;
            
            case 'h': //help
                usage(stdout, NULL);

            case '?':
            default:
                usage(stderr, NULL);
        }
    }
    
    // check mode
    if ( !options.inject && !options.sniff && !options.convert_to_raw && !options.convert_to_hexstr && !options.print_dis_example ) {
        usage(stderr, "\nError: no mode selected.\n");
    }
    
    if ( options.inject && options.sniff ) {
        usage(stderr, "\nError: too many modes selected, see -s and -p options.\n");
    }
    
    if ( options.convert_to_raw && options.convert_to_hexstr ) {
        usage(stderr, "\nError: too many conversions selected, see -x and -y options.\n");
    }
    
    return 1;
}

#endif /* __ARGPARSER_H__ */

