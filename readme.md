# Pcap test

- 강의: S-dev 네트워크 보안<br>
- 마감일: July 13, 2023<br>
- 상태: 완료<br>
- 유형: 과제

# 목차
[과제 내용](#과제-내용)<br>
[ㄴ상세](#상세)<br><br>
[과제 해결 과정](#과제-해결-과정)<br>
[ㄴ0. 스켈레톤 코드](#0-스켈레톤-코드)<br>
[ㄴ1. Ethernet Header의 src mac / dst mac 출력](#1-ethernet-header의-src-mac--dst-mac-출력)<br>
[ㄴ2. IP Header의 src ip / dst ip](#2-ip-header의-src-ip--dst-ip)<br>
[ㄴ3. TCP Header의 src port / dst port](#3-tcp-header의-src-port--dst-port)<br>
[ㄴ4. Payload(Data)의 hexadecimal value(최대 10바이트까지만)](#4-payloaddata의-hexadecimal-value최대-10바이트까지만)<br><br>
[결과](#결과)<br><br>
[전체 코드](#전체-코드)<br>

# 과제 내용

송수신되는 packet을 capture하여 중요 정보를 출력하는 C/C++ 기반 프로그램을 작성하라.

```
1. Ethernet Header의 src mac / dst mac
2. IP Header의 src ip / dst ip
3. TCP Header의 src port / dst port
4. Payload(Data)의 hexadecimal value(최대 10바이트까지만)
```

### 상세

- TCP packet이 잡히는 경우 "ETH + IP + TCP + DATA" 로 구성이 된다. 이 경우(TCP packet이 잡혔다고 판단되는 경우만)에만 1~4의 정보를 출력하도록 한다(Data의 크기가 0여도 출력한다).
- 각각의 Header에 있는 특정 정보들(mac, ip, port)를 출력할 때, 노다가(packet의 시작위치로부터 일일이 바이트 세어 가며)로 출력해도 되는데 불편함.
- 이럴 때 각각의 Header 정보들이 structure로 잘 선언한 파일이 있으면 코드의 구성이 한결 간결해진다. 앞으로 가급적이면 네트워크 관련 코드를 작성할 할 때에는 libnet 혹은 자체적인 구조체를 선언하여 사용하도록 한다.
    - [http://packetfactory.openwall.net/projects/libnet](http://packetfactory.openwall.net/projects/libnet) > Latest Stable Version: 1.1.2.1 다운로드(libnet.tar.gz) > include/libnet/libnet-headers.h
    - libnet-headers.h 안에 있는 본 과제와 직접적으로 관련된 구조체들 :
        - struct libnet_ethernet_hdr (479 line)
        - struct libnet_ipv4_hdr (647 line)
        - struct libnet_tcp_hdr (1519 line)
- [pcap-test](https://gitlab.com/gilgil/pcap-test) 코드를 skeleton code으로 하여 과제를 수행해야 하며, pcap_findalldevs, pcap_compile, pcap_setfilter, pcap_lookupdev, pcap_loop API는 사용하지 않는다(인터넷에 돌아다니는 코드에 포함되어 있는 함수들이며, 본 함수들이 과제의 코드에 포함되는 경우 과제를 베낀 것으로 간주함).
- [Dummy interface를 이용하여 디버깅을 쉽게할 수 있는 방법](https://gilgil.gitlab.io/2020/07/23/1.html)을 알면 과제 수행에 도움이 된다.

# 과제 해결 과정

### 0. 스켈레톤 코드

코드의 이해를 돕기 위해 최대한 자세하게 주석을 작성해봤습니다.

틀린 부분이 있다면 누구든 지적해주시면 감사하겠습니다.

```c
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
/* parse()함수 인자
1. param 구조체의 포인터 
2. argc: 입력된 인자의 Count
3. argv: 실제 입력된 인자의 Value
*/
	if (argc != 2) {
		usage();
		return false;
		// argc가 2가 아니라면, usage() 함수 호출 후 return false
	}
	param->dev_ = argv[1];
	return true;
  // argc가 2라면 param 구조체의 dev_ 변수에 인자값(argv[1])으로 설정 후 return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
// parse 함수 호출, param 구조체의 포인터, 입력된 인자의 Count, 입력된 인자의 Value를 인자값으로 넘겨줌
// parse() 함수에서 argc가 2가 아니라면 false가 리턴되므로 main()함수에서도 return -1이 발생함

	char errbuf[PCAP_ERRBUF_SIZE];
  // PCAP_ERRBUF_SIZE는 pcap.h 파일에서 256바이트로 정의되어 있음
  // pcap.h: https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/pcap.h
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
  /*
  1. 패킷 캡처를 위해 열려는 네트워크 디바이스의 이름
  2. 패킷당 캡처할 최대 바이트 수를 지정
     BUFSIZ가 어디에 정의 되어 있는지는 모르겠습니다..
  3. promiscuous mode(1) 설정
  4. millisecond 단위로 Timeout 지정 
  5. 에러가 발생하는 경우 리턴할 버퍼
  */
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
  // pcap 결과가 NULL인 경우 표준 에러를 장치명과 에러메세지와 함께 출력

  /* 에러가 발생하여 errbuf에 에러 메세지가 저장되었지만, pcap이 NULL이 아니라면? 
  이라는 생각을 잠깐 했었습니다.
  하지만, pcap doc을 확인해보니, pcap_open_live 함수가 실행에 실패하게 되면 pcap은 반드시
  NULL값으로 설정된다고 합니다. 이 부분은 더이상 수정할 필요가 없을 것 같습니다.
  doc Link: https://www.ibm.com/docs/en/aix/7.3?topic=p-pcap-open-live-subroutine
  */

	while (true) {
		struct pcap_pkthdr* header;
    /* pcap_pkthdr는 패킷 헤더를 담는 구조체
    
		struct pcap_pkthdr {
      struct timeval ts;      /* time stamp(타임스탬프) */
      bpf_u_int32 caplen;  /* length of portion present(한번에 읽어들인 패킷의 길이) */
      bpf_u_int32 len;       /* length this packet (off wire)(실제 패킷의 전체 길이) */
    };

    */
		const u_char* packet;
    // packet이라는 이름의 변수가 unsigned char형 데이터의 주소를 가리키며, 값을 변경할 수 없음
		int res = pcap_next_ex(pcap, &header, &packet);
    /* pcap_next_ex 함수 인자
    1. pcap_open_live를 통해 오픈된 pcap
    2. header 데이터를 저장하는 변수
    3. packet 데이터를 저장하는 변수 
    return: 성공 시 1을 반환하며, timeout이 될 경우 0을 반환, 에러시 -1을 반환, EOF시 -2를 반환함
    */
		if (res == 0) continue;
    // timeout시 continue를 통해 while문 재진입
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
      /* pcap.h에서 PCAP_ERROR와 PCAP_ERROR_BREAK는 다음과 같이 define 되어있음
			#define   PCAP_ERROR       -1
			#define   PCAP_ERROR_BREAK -2
			따라서, 에러가 발생한 경우 해당 에러 메세지를 출력해주고, while문에서 탈출
      */
		}
		printf("%u bytes captured\n", header->caplen);
		// header 구조체에 저장된 caplen(한번에 읽어들인 패킷의 길이)를 출력
	}

	pcap_close(pcap);
	// open된 pcap을 close처리
}
```

### 1. Ethernet Header의 src mac / dst mac 출력

1. ethernet_hdr 구조체를 정의해야 합니다.
    
    libnet-headers.h에서 ethernet_hdr 구조체를 사용하면 됩니다.
    
    ```c
    struct libnet_ethernet_hdr
    {
        u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
        u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
        u_int16_t ether_type;                 /* protocol */
    };
    ```
    
2. MAC 주소는 6바이트이므로 `#difine ETHER_ADDR_LEN 6` 도 추가합니다.
3. packet 포인터를 Ethernet Header 구조체 포인터로 형변환 합니다.
    
    ```c
    struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
    /* 
    struct libnet_ethernet_hdr* eth_hdr
    -> eth_hdr라는 이름의 struct libnet_ethernet_hdr 타입의 포인터를 선언
    
    (struct libnet_ethernet_hdr*)packet
    -> packet이 가리키는 메모리의 시작 위치에서 struct libnet_ethernet_hdr 구조체의 크기만큼의 메모리를 struct libnet_ethernet_hdr 형식으로 해석
    */
    ```
    
4. src mac / dst mac을 출력해주는 함수를 생성합니다.
    
    ```c
    void printMac(u_int8_t* src_mac, u_int8_t* dst_mac){
            printf("Source Mac: %02x %02x %02x %02x %02x %02x\n", src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
            printf("Destination Mac: %02x %02x %02x %02x %02x %02x\n", dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
    }
    /*
    libnet_ethernet_hdr 구조체에서 mac주소는 `ETHER_ADDR_LEN`크기의 배열로 관리하기 때문에, 6바이트값을 mac[0] ~ mac[5]로 출력합니다.
    */
    ```
    
5. main함수에서 printMac 함수를 호출합니다.
    
    ```c
    printMac(eth_hdr -> ether_shost, eth_hdr -> ether_dhost);
    //eth_hdr의 ether_shost, ether_dhost를 인자값으로 호출합니다.
    ```
    
6. Ether Type이 IPv4가 아닌 경우 뒷 내용은 출력하지 않습니다.
    
    ```c
    if(ntohs(eth_hdr -> ether_type) != ETHER_TYPE_IP) continue;
    ```
    

### 2. IP Header의 src ip / dst ip

1. IPv4의 구조체를 정의합니다.
    
    libnet-headers.h에서 libnet_ipv4_hdr 구조체를 사용하면 됩니다.
    
    ```c
    struct libnet_ipv4_hdr
    {
    #if (LIBNET_LIL_ENDIAN)
        u_int8_t ip_hl:4,      /* header length */
               ip_v:4;         /* version */
    #endif
    #if (LIBNET_BIG_ENDIAN)
        u_int8_t ip_v:4,       /* version */
               ip_hl:4;        /* header length */
    #endif
        u_int8_t ip_tos;       /* type of service */
    #ifndef IPTOS_LOWDELAY
    #define IPTOS_LOWDELAY      0x10
    #endif
    #ifndef IPTOS_THROUGHPUT
    #define IPTOS_THROUGHPUT    0x08
    #endif
    #ifndef IPTOS_RELIABILITY
    #define IPTOS_RELIABILITY   0x04
    #endif
    #ifndef IPTOS_LOWCOST
    #define IPTOS_LOWCOST       0x02
    #endif
        u_int16_t ip_len;         /* total length */
        u_int16_t ip_id;          /* identification */
        u_int16_t ip_off;
    #ifndef IP_RF
    #define IP_RF 0x8000        /* reserved fragment flag */
    #endif
    #ifndef IP_DF
    #define IP_DF 0x4000        /* dont fragment flag */
    #endif
    #ifndef IP_MF
    #define IP_MF 0x2000        /* more fragments flag */
    #endif 
    #ifndef IP_OFFMASK
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    #endif
        u_int8_t ip_ttl;          /* time to live */
        u_int8_t ip_p;            /* protocol */
        u_int16_t ip_sum;         /* checksum */
        struct in_addr ip_src, ip_dst; /* source and dest address */
    };
    
    /* 구조체에서 아래와 같은 #if, #endif 문이 보입니다.
    #if (LIBNET_LIL_ENDIAN)
        u_int8_t ip_hl:4,      
               ip_v:4;         
    #endif
    #if (LIBNET_BIG_ENDIAN)
        u_int8_t ip_v:4,       
               ip_hl:4;       
    #endif
    
    검색을 해보니, 이는 조건부 컴파일 지시자라고 합니다.
    컴파일 환경이 리틀앤디언인지, 빅앤디언인지에 따라 컴파일을 다르게 할 수 있는 것 입니다.
     
    리틀 앤디언인 경우 패킷 헤더는 ip_hl, ip_v 순서대로 해석해야하며, 빅앤디언인 경우 ip_v, ip_hl 순서대로 해석해야 하기 때문입니다.
    코드가 정상적으로 동작하게 하려면 다음과 같은 두 가지 방법이 있습니다.
    1. `#difine LIBNET_LIL_ENDIAN` 또는 `#difine LIBNET_BIG_ENDIAN` 매크로를 선언
    2. 컴파일을 할 때 `-DLIBNET_LIL_ENDIAN` 또는 `-DLIBNET_BIG_ENDIAN` 옵션을 추가
    
    저는 2번을 택하여 makefile을 수정했습니다.
    
    makefile code
    LDLIBS += -lpcap
    CFLAGS += -DLIBNET_LIL_ENDIAN
    
    all: pcap-test
    
    pcap-test:  pcap-test.c
    
    clean:
            rm -f pcap-test *.o
    */
    ```
    
2. Ethernet 헤더 다음에 오는 IPv4 헤더에 대한 packet 포인터를 생성합니다.
    
    ```c
    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(*eth_hdr));
    ```
    
3. src ip / dst ip를 출력해주는 함수를 생성합니다.
    
    ```c
    void printIP(struct in_addr src_ip, struct in_addr dst_ip) {
        printf("Source IP: %d.%d.%d.%d\n",
               src_ip.s_addr & 0xFF,
               (src_ip.s_addr >> 8) & 0xFF,
               (src_ip.s_addr >> 16) & 0xFF,
               (src_ip.s_addr >> 24) & 0xFF);
        printf("Destination IP: %d.%d.%d.%d\n",
               dst_ip.s_addr & 0xFF,
               (dst_ip.s_addr >> 8) & 0xFF,
               (dst_ip.s_addr >> 16) & 0xFF,
               (dst_ip.s_addr >> 24) & 0xFF);
    }
    ```
    
4. main함수에서 printIP함수를 호출합니다.
    
    ```c
    printIP(ip_hdr -> ip_src, ip_hdr -> ip_dst);
    ```
    
5. TCP 이외의 패킷은 출력하지 않도록 합니다.
    
    ```c
    if(ip_hdr -> ip_p != PROTOCOL_TYPE_TCP) continue;
    ```
    

### 3. TCP Header의 src port / dst port

1. TCP의 구조체를 정의합니다.
    
    libnet-headers.h에서 libnet_tcp_hdr 구조체를 사용하면 됩니다.
    
    ```c
    struct libnet_tcp_hdr
    {
        u_int16_t th_sport;       /* source port */
        u_int16_t th_dport;       /* destination port */
        u_int32_t th_seq;          /* sequence number */
        u_int32_t th_ack;          /* acknowledgement number */
    #if (LIBNET_LIL_ENDIAN)
        u_int8_t th_x2:4,         /* (unused) */
               th_off:4;        /* data offset */
    #endif
    #if (LIBNET_BIG_ENDIAN)
        u_int8_t th_off:4,        /* data offset */
               th_x2:4;         /* (unused) */
    #endif
        u_int8_t  th_flags;       /* control flags */
    #ifndef TH_FIN
    #define TH_FIN    0x01      /* finished send data */
    #endif
    #ifndef TH_SYN
    #define TH_SYN    0x02      /* synchronize sequence numbers */
    #endif
    #ifndef TH_RST
    #define TH_RST    0x04      /* reset the connection */
    #endif
    #ifndef TH_PUSH
    #define TH_PUSH   0x08      /* push data to the app layer */
    #endif
    #ifndef TH_ACK
    #define TH_ACK    0x10      /* acknowledge */
    #endif
    #ifndef TH_URG
    #define TH_URG    0x20      /* urgent! */
    #endif
    #ifndef TH_ECE
    #define TH_ECE    0x40
    #endif
    #ifndef TH_CWR   
    #define TH_CWR    0x80
    #endif
        u_int16_t th_win;         /* window */
        u_int16_t th_sum;         /* checksum */
        u_int16_t th_urp;         /* urgent pointer */
    };
    ```
    
2. IPv4 헤더 다음에 오는 TCP 헤더에 대한 packet 포인터를 생성합니다.
    
    ```c
    struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(*eth_hdr) + ip_hdr -> ip_hl*4);
    /*
    TCP 헤더는 패킷의 시작부터 이더넷 헤더의 길이와 IP 헤더의 길이를 더한 곳에 위치하게 됩니다.
    따라서, packet + sizeof(*eth_hdr) + ip_hdr -> ip_hl*4은 tcp header의 시작 위치입니다.
    */
    ```
    
3. src port / dst port를 출력해주는 함수를 생성합니다.
    
    ```c
    void printPORT(u_int16_t src_port, u_int16_t dst_port){
            printf("Soruce Port: %d\n", ntohs(src_port));
            printf("Destination Port: %d\n", ntohs(dst_port));
    }
    ```
    
4. main함수에서 printPORT함수를 호출합니다.
    
    ```c
    printPORT(tcp_hdr -> th_sport, tcp_hdr -> th_dport);
    ```
    

### 4. Payload(Data)의 hexadecimal value(최대 10바이트까지만)

1. TCP 헤더 다음에 오는 Payload(Data)에 대한 packet 포인터를 생성합니다.
    
    ```c
    u_char *data = (u_char *)(packet + sizeof(*eth_hdr) + ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4);
    ```
    
2. Payload(Data)의 length를 확인합니다.
    
    ```c
    int data_len = ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4 + tcp_hdr->th_off * 4);
    ```
    
3. Payload(Data)를 출력해주는 함수를 생성합니다.
    
    ```c
    void printDATA(int data_len, u_char* data){
            if (data_len == 0){
                    printf("Data is Zero Bytes\n");
                    return;
            }
            printf("Data is %d Bytes\n",data_len);
            printf("Data: ");
            if(data_len < 10){
                    for(int i = 0; i <= data_len; i++){
                            printf("%02x ", data[i]);
                            }
            }
            else{
                    for(int i = 0; i <=9; i++){
                            printf("%02x ",data[i]);
                    }
            }
            printf(". . .\n");
    }
    // data_len이 10보다 작을 경우 전체 data를 출력시켜주며, data_len이 10 이상일 경우, data의 10바이트만 출력시킵니다.
    ```
    
4. main함수에서 printDATA함수를 호출합니다.
    
    ```c
    printDATA(data_len, data);
    ```
    

# 결과

> Run Image
> ![run_image](https://concise-egg-c3d.notion.site/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fe2fd14cf-0d9e-4e02-82a1-cd78b93fd16a%2FUntitled.png?id=7292065e-2594-4adc-bdda-71865472e521&table=block&spaceId=cdedcb90-4171-4218-866c-2193f2353645&width=1220&userId=&cache=v2)

# 전체 코드

[Read pcap-test.c](https://github.com/with-developer/pcap_test/blob/main/pcap-test.c)
