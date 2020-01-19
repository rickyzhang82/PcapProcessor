#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
namespace fs = std::filesystem;

#include "EndianPortable.h"
#include "stdlib.h"
#include "Packet.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "PcapFileDevice.h"

const int32_t NUM_PACKETS_TO_READ = 16;
const size_t FIXED_PACKET_SIZE = 1500;
const size_t LINK_LAYER_HEADER_LENGTH = 14;
const fs::path OUTPUT_ROOT("/home/Ricky/Documents/mod-tcpsorter");
const std::string DEFAULT_PACPA_FILE_LIST("pcap.lst");
const std::string MOD_FILE_EXTENSION(".bin");

inline bool readPcapFile(std::string& pcapFileName, pcpp::RawPacketVector& packetVec, int32_t numOfPacketsToRead = NUM_PACKETS_TO_READ)
{
	// use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
	// and create an interface instance that both readers implement
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcapFileName.c_str());

	// verify that a reader interface was indeed created
	if (reader == NULL)
	{
		printf("Error: Cannot determine reader for file type: %s.\n", pcapFileName.c_str());
		return false;
	}

	// open the reader for reading
	if (!reader->open())
	{
		printf("Error: Cannot open file: %s for reading.\n", pcapFileName.c_str());
		return false;
	}

	auto numPacketsRead = reader->getNextPackets(packetVec, numOfPacketsToRead);
	// close the file reader, we don't need it anymore
	reader->close();

	if (numOfPacketsToRead == -1 || numPacketsRead == numOfPacketsToRead)
	{
		return true;
	}
	else
	{
		printf("Error: The actual number of packets (%d) does not meet the expected number (%d).\n", numPacketsRead, numOfPacketsToRead);
		return false;
	}
}

inline uint8_t* tranformPacket(pcpp::RawPacket* pRawPacket, size_t fixedPacketSize, size_t linkLayerHeaderLength)
{
	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(pRawPacket);

	// let's get the IPv4 layer
	pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	// change source IP address
	ipLayer->setSrcIpAddress(pcpp::IPv4Address(std::string("0.0.0.0")));
	// change destination IP address
	ipLayer->setDstIpAddress(pcpp::IPv4Address(std::string("0.0.0.0")));

	// let's get the TCP layer
	pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
	// change source port
	tcpLayer->getTcpHeader()->portSrc = htobe16(0);
	// change destination port
	tcpLayer->getTcpHeader()->portDst = htobe16(0);

	// compute all calculated fields
	parsedPacket.computeCalculateFields();

	// copy over
	auto buff = new uint8_t[fixedPacketSize];
	memset(buff, 0, fixedPacketSize);
	auto modPRawPacket = parsedPacket.getRawPacket();
	auto modPRawData = modPRawPacket->getRawData();
	size_t modPRawDataSize = modPRawPacket->getRawDataLen();

	if (modPRawDataSize > linkLayerHeaderLength)
	{
		// remove link layer 14 bytes
		memcpy(buff, modPRawData + linkLayerHeaderLength, std::min(modPRawDataSize - linkLayerHeaderLength, fixedPacketSize));
	}

	return buff;
}

inline bool writeRawPacketData(uint8_t* pRawData, size_t dataLen, std::string filename, bool shouldAppend)
{
	auto flag = std::fstream::out | std::fstream::binary;

	if (shouldAppend)
	{
		flag |= std::fstream::app;
	}

	std::ofstream b_stream(filename.c_str(), flag);

	if (b_stream)
	{
		b_stream.write(reinterpret_cast<char*>(pRawData), dataLen);
		return (b_stream.good());
	}
	 return false;
}

inline std::string getModFileName(std::string& filename)
{
	fs::path modFilePath(OUTPUT_ROOT);
	modFilePath /= fs::path(filename).stem();
	return modFilePath.string() + MOD_FILE_EXTENSION;
}

inline int processPcapFile(std::string& pcapFileName)
{
	pcpp::RawPacketVector packetVec;

	if (! readPcapFile(pcapFileName, packetVec))
	{
		return 1;
	}

	bool shouldAppend = false;

	for (auto it = packetVec.begin(); it != packetVec.end(); it++)
	{
		auto buff = tranformPacket(*it, FIXED_PACKET_SIZE, LINK_LAYER_HEADER_LENGTH);
		writeRawPacketData(buff, FIXED_PACKET_SIZE, getModFileName(pcapFileName), shouldAppend);
		shouldAppend = true;
		free(buff);
	}

	return 0;
}

inline bool getPcapFileList(std::string& pcapFileListPath, std::vector<std::string>& pcapFileVec)
{
	std::ifstream ifs(pcapFileListPath.c_str());

	if (!ifs.is_open())
	{
		return false;
	}

	std::string line;
	while (std::getline(ifs, line))
	{
		pcapFileVec.push_back(line);
	}

	return true;
}

int main(int argc, char* argv[])
{
	std::string pcapFileListPath;
	std::vector<std::string> pcapFileVec;

	if (2 !=argc)
	{
		pcapFileListPath = DEFAULT_PACPA_FILE_LIST;
	}
	else
	{
		pcapFileListPath = std::string(argv[1]);
	}

	std::cout << "Info: Load pcap file list " << pcapFileListPath << std::endl;

	if (!getPcapFileList(pcapFileListPath, pcapFileVec))
	{
		std::cout << "Error: Failed to load pcap file list " << pcapFileListPath << std::endl;
		return 1;
	}

	for (auto it = pcapFileVec.begin(); it != pcapFileVec.end(); it++)
	{
		int ret = processPcapFile(*it);
		if (0 == ret)
		{
			std::cout << "Info: Succeeded in processing " << *it << std::endl;
		}
		else
		{
			std::cout << "Error: Failed to process " << *it << std::endl;
		}
	}
	return 0;
}
