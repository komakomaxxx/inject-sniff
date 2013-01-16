#include <stdio.h>
#include "hexstring.h"

#define BUFFERSIZE 65535
#define SIZEHEADERNUM 4

#define PACKETHEADER "00 00 1a 00 2F 48 00 00 B4 CD CD 9F 02 00 00 00 10 02 7B 09 A0 00 C7 01 00 00 00 00 00 00 00 00 80 08 3A 01 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78"

#define PACKETCKSUM "00 00 FF FF FF FF"

#define INJECTCOMMAND  "./sniff/sniffPacket -p -i mon0"

#define TRUE 1
#define FALSE 0

int main(int argc,char **argv){
	uint8_t buf[BUFFERSIZE+1];
	char packbuf[BUFFERSIZE*3];
	int i=0,size=0,tmp=0;
	uint8_t *packet,*p; 
	char command[BUFFERSIZE*3+500]; 
	int fd;

	fd= fileno(stdin);
	p = buf;
	while (!feof(stdin)) {
       	    /* Read hexstring */
            tmp =  read(fd,buf+size, BUFFERSIZE-size);
	    size += tmp;
            if(  tmp <= 0 || size == BUFFERSIZE  ) {
            	break;
            }
    	}

	for(i=0;i < size;i++){
	    sprintf(packbuf+(i*3),"%02x ",buf[i]);
	}

	/*取得したバイトストリームをコマンド用に整形*/
	packet = raw_to_hexstr(packbuf,size);

	sprintf(command,"echo \"%s %s%s\" | %s"
		,PACKETHEADER,packbuf,PACKETCKSUM,INJECTCOMMAND);
//	fprintf(stderr,"%s\n",packbuf);fflush(stderr);

	system(command);
}
