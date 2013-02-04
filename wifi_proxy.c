/*
 monitormodeで起動したwifiをソケットを通じて使用するためのプログラム
 引数にポート番号を設定し、任意のポートで待ち受けソケットのポートを指定できる。
	第一引数　キャプチャポート
	第二引数　インジェクションポート
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define INJECT_LOOP_PROCESS "./inject/injectPacket"//インジェクションプログラムパス
//#define INJECT_LOOP_PROCESS "./inject/injectPacket -p -r -i mon"//インジェクションプログラムパス
#define CAPTURE_LOOP_PROCESS "./sniff/sniffPacket"//キャプチャプログラムパス
#define CAPTURE_LOOP_PROCESS_ARG "","-s","-r", "-i","mon0","-f","wlan src 78:78:78:78:78:78"//キャプチャプログラムパス
#define ERR_CODE -1;
#define ADDR_FAMILY AF_INET
#define TRUE !0;
#define FALSE 0;

int serv_sock,sock;

//指定したポート番号のソケットを生成（再生成）、バインド、リッスンしてソケットを返却する
int make_socket( char *port)
{
	int sock;
	int opt_on = 1;
	struct sockaddr_in addr;

	sock = socket( ADDR_FAMILY, SOCK_STREAM, 0);
	if(sock < 0){
		perror("can't create socket err");
		return ERR_CODE;
	}

	//ソケットオプションを設定し、ソケットの再利用を行う
	if(setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt_on, sizeof(opt_on))){
		perror("set socket option err");
		return ERR_CODE;
	}

	//socketに名前をつける
	addr.sin_family = ADDR_FAMILY;
	addr.sin_port = htons(atoi(port));
	addr.sin_addr.s_addr = INADDR_ANY;
	
	if(bind( sock, (struct sockaddr *)&addr, sizeof(addr))){
		perror("bind err");
		return ERR_CODE;
	}

	if(listen( sock, 5)){
		perror("listen que err");
		return ERR_CODE;
	}

	return sock;
}

//文字列が整数値であるかの確認 整数値でなければ０を、そうでなければ０以外を返す。
int num_check( char *check_str)
{
	while(isdigit(*check_str)) check_str++;
	if(*check_str == '\0') return TRUE else FALSE;
}

int main_loop( char *p_path, char *set_port, FILE *fd)
{
	int len;
	char buf[1024];
	struct sockaddr_in client;

	serv_sock = make_socket(set_port);

	while(1){
		len = sizeof(client);
printf("wait... ");
fflush(stdout);
		sock = accept( serv_sock, (struct sockaddr *)&client, (socklen_t *)&len);
printf("accept !!");
fflush(stdout);
//printf("[%d]\n",sock);

		if(!fork()){
			close(serv_sock);
			if(dup2(sock,fileno(fd)) < 0){
				perror("dup2");
				exit(1);
			}
///			if(execl(p_path," -s -r -i mon0 -f 'src host 248.0.0.1'",NULL)){
			//if(system(p_path)){
			if(execl(p_path,CAPTURE_LOOP_PROCESS_ARG,NULL)){
				perror("execl");
				exit(1);
			}
		}
		close(sock);
	}
}

void my_exit( int sig)
{
        shutdown(serv_sock,SHUT_RDWR);
        shutdown(sock,SHUT_RDWR);
        close(serv_sock);
        close(sock);
	perror("server...exit");
        exit(1);
}

int main( int argc, char **argv)
{
	char capArg[6];
	char injArg[6];
	signal( SIGCHLD, SIG_IGN);
	signal( SIGINT, my_exit);

	if( argc != 3){
		strcpy(capArg,"10000");
		strcpy(injArg,"9999");
	}else{
		strcpy(capArg,argv[1]);
		strcpy(injArg,argv[2]);
	}

	if(!fork()){
		main_loop(CAPTURE_LOOP_PROCESS,capArg,stdout);
	}

	if(!fork()){
		main_loop(INJECT_LOOP_PROCESS,injArg,stdin);
	}
	while(1);
}
