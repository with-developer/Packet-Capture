# Pcap test

강의: S-dev(네트워크 보안)
마감일: July 13, 2023
상태: 진행 중
유형: 과제



# 과제 내용
---

송수신되는 packet을 capture하여 중요 정보를 출력하는 C/C++ 기반 프로그램을 작성하라.

```
1. Ethernet Header의 src mac / dst mac
2. IP Header의 src ip / dst ip
3. TCP Header의 src port / dst port
4. Payload(Data)의 hexadecimal value(최대 10바이트까지만)
```

# 과제 해결 과정

---

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

1. MAC 주소는 6바이트이므로 `#difine ETHER_ADDR_LEN 6` 도 추가합니다.
2. packet 포인터를 Ethernet Header 구조체 포인터로 형변환 합니다.

```c
struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
/* 
struct libnet_ethernet_hdr* eth_hdr
-> eth_hdr라는 이름의 struct libnet_ethernet_hdr 타입의 포인터를 선언

(struct libnet_ethernet_hdr*)packet
-> packet이 가리키는 메모리의 시작 위치에서 struct libnet_ethernet_hdr 구조체의 크기만큼의 메모리를 struct libnet_ethernet_hdr 형식으로 해석
*/
```

1. src mac / dst mac을 출력해주는 함수를 생성합니다.

```c
void printMac(u_int8_t* src_mac, u_int8_t* dst_mac){
        printf("Source Mac: %02x %02x %02x %02x %02x %02x\n", src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
        printf("Destination Mac: %02x %02x %02x %02x %02x %02x\n", dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
}
/*
libnet_ethernet_hdr 구조체에서 mac주소는 `ETHER_ADDR_LEN`크기의 배열로 관리하기 때문에, 6바이트값을 mac[0] ~ mac[5]로 출력합니다.
*/
```

1. main()함수에서 printMac 함수를 호출합니다.

```c
printMac(eth_hdr -> ether_shost, eth_hdr -> ether_dhost);
```