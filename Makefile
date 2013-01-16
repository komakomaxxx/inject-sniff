all:
	cd sniff/;make
	cd inject/;make
	gcc -o wifi_proxy wifi_proxy.c 
clean:
	rm sniff/sniffPaket
	rm inject/injectPacket
	rm wifi_proxy

