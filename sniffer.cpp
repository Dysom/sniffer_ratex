#include "sniffer.h"

std::string Sniffer::getProtocolStr(unsigned char protocol) const {
	std::string protocolStr;

	switch (protocol)
	{
	case IPPROTO_UDP:
		protocolStr = "UDP";
		break;
	case IPPROTO_TCP:
		protocolStr = "TCP";
		break;
	case IPPROTO_ICMP:
		protocolStr = "ICMP";
		break;
	case IPPROTO_IGMP:
		protocolStr = "IGMP";
		break;
	case 3:
		protocolStr = "Bluetooth RFCOMM";
		break;
	case IPPROTO_ICMPV6:
		protocolStr = "ICMPv6";
		break;
	case 113:
		protocolStr = "PGM";
		break;
	default:
		protocolStr = "unrecognized";
		break;
	}

	return protocolStr;
}

Sniffer::Sniffer(const std::string& ipStr, std::ostream& fileOutput) : fOut(fileOutput) {
	if (WSAStartup(MAKEWORD(2, 2), &WSAData)) {
		std::cout << "Error at WSAStartup()\n";
		error = true;
		return;
	}

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	if (sock == INVALID_SOCKET) {
		std::cout << "Error at socket: ";
		std::cout << WSAGetLastError() << "\n";
		error = true;
		return;
	}

	ZeroMemory(&sockAddress, sizeof(sockAddress));
	sockAddress.sin_family = AF_INET;	
		
	if (inet_pton(AF_INET, ipStr.c_str(), &(sockAddress.sin_addr)) != 1) {
		std::cout << "Bad ip address: ";
		std::cout << WSAGetLastError() << "\n";
		error = true;
		return;
	}

	if (bind(sock, (SOCKADDR*)&sockAddress, sizeof(SOCKADDR)) == SOCKET_ERROR) {
		std::cout << "Bind failed: ";
		std::cout << WSAGetLastError() << "\n";
		error = true;
		return;
	}

	unsigned long fOne = 1;

	if (ioctlsocket(sock, 0x98000001, &fOne) != NOERROR) {
		std::cout << "ioctlsocket failed\n";
		error = true;
		return;
	}
}

Sniffer::~Sniffer() {
	closesocket(sock);
	WSACleanup();
}

void Sniffer::stop() {
	if (shutdown(sock, SD_RECEIVE) == SOCKET_ERROR) {
		std::cout << "shutdown failed: ";
		std::cout << WSAGetLastError() << "\n";
		error = true;
	}
	active = false;
}

void Sniffer::process() {
	while (active && error == false) {

		receivedBytesCount = recv(sock, (char*)&buffer[0], bufferSize, 0);

		if (receivedBytesCount >= sizeof(IPHeader)) {
			IPHeader* iph = (IPHeader*)buffer;

			/*if (sockAddress.sin_addr.S_un.S_addr != iph->srcAddress && sockAddress.sin_addr.S_un.S_addr != iph->destAddress) {
				continue;
			}*/

			unsigned short ipHeaderLength = ((iph->versionAndLength & 0x0F) << 2);
			unsigned short packetTotalLength = ntohs(iph->packetTotalLength);

			fOut << "IP HEADER:\n";

			outputIPHeader(iph);

			if (iph->protocol == IPPROTO_TCP) {
				if (packetTotalLength >= ipHeaderLength + sizeof(TCPHeader)) {
					TCPHeader* tcph = (TCPHeader*)(buffer + ipHeaderLength);
					
					fOut << "\nTCP HEADER:\n";

					outputTCPHeader(tcph);
				}
			}

			if (iph->protocol == IPPROTO_UDP) {
				if (packetTotalLength >= ipHeaderLength + sizeof(UDPHeader)) {
					UDPHeader* udph = (UDPHeader*)(buffer + ipHeaderLength);

					fOut << "\nUDP HEADER:\n";

					fOut << "source port: " << ntohs(udph->srcPort) << fieldsSplitter;
					fOut << "destination port: " << ntohs(udph->destPort) << fieldsSplitter;
					fOut << "datagramLength: " << ntohs(udph->datagramLength) << fieldsSplitter;
					fOut << "checksum: " << ntohs(udph->controlSum) << fieldsSplitter;
				}
			}

			fOut << packetsSplitter;
		}
	}
}

void Sniffer::outputIPHeader(const IPHeader* iph) {
	fOut << "version: " << ((iph->versionAndLength & 0xF0) >> 4) << fieldsSplitter;
	fOut << "headerLength: " << ((iph->versionAndLength & 0x0F) << 2) << fieldsSplitter;
	fOut << "tos: " << (int)(iph->tos) << fieldsSplitter;
	fOut << "totalLength: " << ntohs(iph->packetTotalLength) << fieldsSplitter;
	fOut << "id: " << ntohs(iph->id) << fieldsSplitter;
	fOut << "flags: " << (ntohs(iph->flagsAndOffset) >> 13) << fieldsSplitter;
	fOut << "offset: " << (ntohs(iph->flagsAndOffset) & 0x1FFF) << fieldsSplitter;
	fOut << "ttl: " << (int)(iph->ttl) << fieldsSplitter;
	fOut << "protocol: " << getProtocolStr(iph->protocol) << fieldsSplitter;
	fOut << "controlSum: " << ntohs(iph->controlSum) << fieldsSplitter;

	inet_ntop(AF_INET, &(iph->srcAddress), charStr, INET_ADDRSTRLEN);
	fOut << "source IP: " << charStr << fieldsSplitter;

	inet_ntop(AF_INET, &(iph->destAddress), charStr, INET_ADDRSTRLEN);
	fOut << "destination IP: " << charStr << fieldsSplitter;
}

void Sniffer::outputTCPHeader(const TCPHeader* tcph) {
	fOut << "source port: " << ntohs(tcph->srcPort) << fieldsSplitter;
	fOut << "destination port: " << ntohs(tcph->destPort) << fieldsSplitter;
	fOut << "sequenceNumber: " << ntohl(tcph->sequenceNumber) << fieldsSplitter;
	fOut << "acknowledgmentNumber: " << ntohl(tcph->ackNumber) << fieldsSplitter;
	fOut << "tcpHeaderLength: " << (int)(tcph->headerLengthAndReserve >> 4) * 4 << fieldsSplitter;
	fOut << "flags: {";
	fOut << "NS: " << (tcph->headerLengthAndReserve & 1) << ", ";

	fOut << "CWR: " << ((tcph->flags >> 7) & 1) << ", ";
	fOut << "ECE: " << ((tcph->flags >> 6) & 1) << ", ";
	fOut << "URG: " << ((tcph->flags >> 5) & 1) << ", ";
	fOut << "ACK: " << ((tcph->flags >> 4) & 1) << ", ";
	fOut << "PSH: " << ((tcph->flags >> 3) & 1) << ", ";
	fOut << "RST: " << ((tcph->flags >> 2) & 1) << ", ";
	fOut << "SYN: " << ((tcph->flags >> 1) & 1) << ", ";
	fOut << "FIN: " << (tcph->flags & 1);
	fOut << "}" << fieldsSplitter;

	fOut << "windowSize: " << ntohs(tcph->windowsSize) << fieldsSplitter;

	fOut << "checksum: " << ntohs(tcph->controlSum) << fieldsSplitter;
	fOut << "urgent pointer: " << ntohs(tcph->urgentPoint) << fieldsSplitter;
}