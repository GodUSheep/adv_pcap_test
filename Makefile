all : adv_pcap_test

adv_pcap_test: main.o
	g++ -g -o adv_pcap_test main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f adv_pcap_test
	rm -f *.o

