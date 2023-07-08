LDLIBS += -lpcap
CFLAGS += -DLIBNET_LIL_ENDIAN

all: pcap-test

pcap-test:  pcap-test.c

clean:
	rm -f pcap-test *.o
