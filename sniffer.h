#pragma once

#include <iostream>
#include <WS2tcpip.h>
#include <string>

#pragma comment (lib, "ws2_32.lib")



struct IPHeader {
	unsigned char  versionAndLength;
	unsigned char  tos;
	unsigned short packetTotalLength;
	unsigned short id;
	unsigned short flagsAndOffset;
	unsigned char  ttl;
	unsigned char  protocol;
	unsigned short controlSum;
	unsigned long  srcAddress;
	unsigned long  destAddress;
};

struct TCPHeader {
	unsigned short srcPort;
	unsigned short destPort;
	unsigned long sequenceNumber;
	unsigned long ackNumber;
	unsigned char headerLengthAndReserve;
	unsigned char flags;
	unsigned short windowsSize;
	unsigned short controlSum;
	unsigned short urgentPoint;
};

struct UDPHeader {
	unsigned short srcPort;
	unsigned short destPort;	
	unsigned short datagramLength;
	unsigned short controlSum;
};

class Sniffer {
private:
	WSADATA WSAData;
	SOCKET sock;
	SOCKADDR_IN sockAddress;
	bool active = true;
	bool error = false;
	static const int bufferSize = 0x10000;
	unsigned char buffer[bufferSize];
	int receivedBytesCount;	
	std::string fieldsSplitter = "   ";
	std::string packetsSplitter = "\n\n\n";
	char charStr[INET_ADDRSTRLEN];
	std::ostream & fOut;
	std::string getProtocolStr(unsigned char protocol) const;
	void outputIPHeader(const IPHeader* iph);
	void outputTCPHeader(const TCPHeader* tcph);
public:
	Sniffer(const std::string& ipStr, std::ostream & fileOutput);
	~Sniffer();

	void process();
	void stop();
	
	bool hasError() const {
		return error;
	}
};
