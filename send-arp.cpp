#include <iostream>
#include <sstream>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <iomanip>
#include <string>
#include <cstdlib>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}


std::string runCmd(const std::string& cmd) {
	std::string ans = "";
	char buffer[128];
	FILE* pipe = popen(cmd.c_str(), "r");

	if(!pipe) {
		perror("popen failed");
		exit(1);
	}

	try {
		while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
			ans += buffer;
		}
	} catch (...) {
		pclose(pipe);
		throw;
	}

	pclose(pipe);
	return ans;
}

std::string getOtherMacAddr(const std::string& ip) {
	std::string cmd = "ping -c 1 " + ip;
	runCmd(cmd);

	std::string arpCmd = "arp -n " + ip;
	std::string arp_res = runCmd(arpCmd);

	std::string ans = "";
	size_t pos = arp_res.find(ip);

	if (pos != std::string::npos) {
		size_t st = arp_res.find(" ", pos);
		st = arp_res.find_first_not_of(" ", st);
		size_t ed = arp_res.find(" ", st);
		ans = arp_res.substr(st, ed - st);
	}

	return ans;
}


std::string getMyMacAddr(const std::string& iface) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if sock < 0 {
		perror("Failed to create socket");
		exit(1);
	}

	struct ifreq ifr;
	std::memset(&ifr, 0, sizeof(ifr));
	std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);

	if (ioctl())
}


int main(int argc, char* argv[]) {
	char name[] = "양준헌"; 
	printf("[bob13][개발]send-arp[%s]", name);
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;
	std::string interface = "eth0";
	std::string myMacAddr = getMyMacAddr(interface);

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = myMacAddr;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = myMacAddr;
	packet.arp_.sip_ = htonl(Ip(argv[1]));  // IP to disguise
	packet.arp_.tmac_ = getOtherMacAddress(argv[2]);
	packet.arp_.tip_ = htonl(Ip(argv[2]));	 // IP to target

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
