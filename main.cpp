#include <iostream>
#include <chrono>
#include <csignal>
#include "Windows.h"
#include "PcapLiveDeviceList.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "IPv4Layer.h"
#include "SystemUtils.h"

using namespace std;

vector<pcpp::PcapLiveDevice*> interfeces_list;
int selected_interface = -1;

struct PocketStats {
	int allPacketCount;
	int shellCodePackets;
	int uncheckedPackets;
};

PocketStats statistics;

static std::string base64Decode(const std::string &in)
{
    std::string out;
    std::vector<int> T(256, -1);

    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val = 0, valb = -8;

    for (unsigned char c : in) {
        if (T[c] == -1) break;

        val = (val << 6) + T[c];
        valb += 6;

        if (valb >= 0) {
            out.push_back(char((val>>valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

const std::string currentDateTime() 
{
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);

    return buf;
}

int detectFunctionsSignatures(string& data) 
{
	vector<string> function_patterns = {"WinExec", "reg", "shell", "proxy", "WinHttp", "recv", "send", "socket", "cmd", ".exe", ".dll", 
		".ps1", ".vbs", ".py", ".js", ".bat", "C:\\Windows\\System32\\cmd.exe", "cmd.exe", "net user", "schtasks.exe", "-EncodedCommand",
		"Software\\\\Microsoft", "net localgroup", "net use", "mstsc.exe", "reg delete",
		"reg add", "cscript.exe", "wscript.exe", "powershell.exe", "stack", "heap", "asm", "VirtualAllocEx", "VirtualFree", "OpenProcess", 
		"WriteProcessMemory", "CreateRemoteThread", "LoadLibrary", "FindWindowA", "CreateThread"};
	int count = 0;

    for (const std::string& pattern : function_patterns) {
        if (data.find(pattern) != std::string::npos) {
            count++;
        }
    }

	return count;
}

int detectNops(string& data) 
{
	int nops_max_sequence = 0;
	int current_sequence = 0;

	for (const auto& c : data) {
		if (c == 0x90) {
			current_sequence++;
			nops_max_sequence = max(current_sequence, nops_max_sequence);
		} else {
			current_sequence = 0;
		}
	}

	return nops_max_sequence;
}

bool isInAddressRange(uint32_t value, uint32_t lowerLimit, uint32_t upperLimit) {
    return value >= lowerLimit && value <= upperLimit;
}

bool checkForMaliciousCode(const std::string& inputData, uint32_t lowerLimit, uint32_t upperLimit) {
    if (inputData.length() < 4) {
        return false;
    }

    for (size_t i = 0; i <= inputData.length() - 4; i++) {
        uint32_t currentValue = (static_cast<uint8_t>(inputData[i]) << 24) |
                                (static_cast<uint8_t>(inputData[i + 1]) << 16) |
                                (static_cast<uint8_t>(inputData[i + 2]) << 8) |
                                static_cast<uint8_t>(inputData[i + 3]);

        if (isInAddressRange(currentValue, lowerLimit, upperLimit)) {
            return true;
        }
    }

    return false;
}

int scanTcpData(pcpp::TcpLayer* tcpLayer) 
{
	if (tcpLayer == NULL) return -1;

	string raw_data(reinterpret_cast<char*>(tcpLayer->getLayerPayload()), tcpLayer->getLayerPayloadSize());
	
	int result_func_sign = detectFunctionsSignatures(raw_data);
	int nops = detectNops(raw_data);
	int check_ret_arddrs = 0;

	const std::vector<std::pair<uint32_t, uint32_t>> ret_addrs_vector = {
        {0x61b6b000, 0x61b6c000},
        {0x6ff1b700, 0x6ff1b800},
        {0x60505000, 0x60506000}
    };

	for (int i = 0; i < 3; i++) {
		check_ret_arddrs += checkForMaliciousCode(raw_data, ret_addrs_vector[i].first, ret_addrs_vector[i].second);
	}

	if ((nops >= 5) || (result_func_sign > 0) || (check_ret_arddrs > 0)) {
		return 1;
	} else {
		string decoded_data = base64Decode(raw_data);

		result_func_sign = detectFunctionsSignatures(decoded_data);
		nops = detectNops(decoded_data);

		for (int i = 0; i < 3; i++) {
			check_ret_arddrs += checkForMaliciousCode(raw_data, ret_addrs_vector[i].first, ret_addrs_vector[i].second);
		}

		if ((nops >= 5) || (result_func_sign > 0) || (check_ret_arddrs > 0))
			return 1;
	}

	return 0;
}

int scanHttpData(pcpp::HttpResponseLayer* httpLayer, pcpp::TcpLayer* tcpLayer) 
{
	if ((httpLayer == NULL) || (tcpLayer == NULL)) return -1;

	string raw_data(reinterpret_cast<char*>(tcpLayer->getLayerPayload()), tcpLayer->getLayerPayloadSize());
	
	int result_func_sign = detectFunctionsSignatures(raw_data);
	int nops = detectNops(raw_data);
	int check_ret_arddrs = 0;

	const std::vector<std::pair<uint32_t, uint32_t>> ret_addrs_vector = {
        {0x61b6b000, 0x61b6c000},
        {0x6ff1b700, 0x6ff1b800},
        {0x60505000, 0x60506000}
    };

	for (int i = 0; i < 3; i++) {
		check_ret_arddrs += checkForMaliciousCode(raw_data, ret_addrs_vector[i].first, ret_addrs_vector[i].second);
	}

	if ((nops >= 5) || (result_func_sign > 0) || (check_ret_arddrs > 0)) {
		return 1;
	} else {
		string decoded_data = base64Decode(raw_data);

		result_func_sign = detectFunctionsSignatures(decoded_data);
		nops = detectNops(decoded_data);

		for (int i = 0; i < 3; i++) {
			check_ret_arddrs += checkForMaliciousCode(raw_data, ret_addrs_vector[i].first, ret_addrs_vector[i].second);
		}

		if ((nops >= 5) || (result_func_sign > 0) || (check_ret_arddrs > 0))
			return 1;
	}

	return 0;
}


int scanPacket(pcpp::Packet& packet) 
{
	int result_tcp = 0, result_http = 0;

	result_tcp = scanTcpData(packet.getLayerOfType<pcpp::TcpLayer>());
	result_http = scanHttpData(packet.getLayerOfType<pcpp::HttpResponseLayer>(), packet.getLayerOfType<pcpp::TcpLayer>());

	return max(result_tcp, result_http);
}

static void onPacketArrives(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* arg)
{
    pcpp::Packet parsedPacket(packet);
	PocketStats* stats = (PocketStats*) arg;

	stats->allPacketCount++;

	int result_of_scan = scanPacket(parsedPacket);

	if (result_of_scan == -1) {
		stats->uncheckedPackets++;
	} else if (result_of_scan == 1) {
		stats->shellCodePackets++;

		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
		cout << currentDateTime() << " Warning: packet may contains shellcode:" << endl;

		pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
		pcpp::HttpResponseLayer* httpLayer = parsedPacket.getLayerOfType<pcpp::HttpResponseLayer>();
		pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
		string raw_data (reinterpret_cast<char*>(tcpLayer->getLayerPayload()), tcpLayer->getLayerPayloadSize());
		
		if (httpLayer != NULL) {
			cout << "Type: HTTP; From: " << ipv4Layer->getSrcIPv4Address() << ":" << tcpLayer->getSrcPort() << " to " << ipv4Layer->getDstIPv4Address() << ":" << tcpLayer->getDstPort() << "; Data: " <<
			endl << raw_data << endl;
		} else {
			cout << "Type: TCP; From: " << ipv4Layer->getSrcIPv4Address() << ":" << tcpLayer->getSrcPort() << " to " << ipv4Layer->getDstIPv4Address() << ":" << tcpLayer->getDstPort() << "; Data: " <<
			endl << raw_data << endl;
		}	

		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15);
	}

	if ((stats->allPacketCount % 100) == 0) {
		cout << currentDateTime() << " >> Captured packets: " << stats->allPacketCount << "; " 
		<< "Shell code detected: " << stats->shellCodePackets << "; Unchecked packets: " << stats->uncheckedPackets << endl;
	}
}

void printHelp() {
	cout << "Usage: cmd [arg]:" << endl
	<< "   h                         -  help" << endl
	<< "   q                         -  quit" << endl
	<< "   v                         -  view list of interfaces" << endl
	<< "   s [number_of_interface]   -  choose inteface and start sniffering traffing to detect shellcode";
}

void printAllInterfaces() {
	interfeces_list = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();

	cout << "List of interfaces:" << endl << endl;

	for (int i = 0; i < interfeces_list.size(); i++) {
		cout << i + 1 << ". " << interfeces_list[i]->getDesc() << ":" << std::endl
		<< "   Interface name:        " << interfeces_list[i]->getName() << std::endl
		<< "   IPv4:                  " << interfeces_list[i]->getIPv4Address() << std::endl
		<< "   IPv6:                  " << interfeces_list[i]->getIPv6Address() << std::endl
		<< "   MAC address:           " << interfeces_list[i]->getMacAddress() << std::endl;
	}
}

void startShiffing() {
	if (selected_interface == -1) {
		std::cerr << "Error: interface was not choosen";
		return;
	}

	pcpp::PcapLiveDevice* current_interface = interfeces_list[selected_interface];

	if (!current_interface->open())
	{
		std::cerr << "Error with interface: not open";
		return;
	}

	std::cout << "Starting pockets sniffering..." << std::endl << "Input <c> to stop (and wait a few second)" << endl;
	current_interface->startCapture(onPacketArrives, &statistics);
	
	string choice;

	while(1) {
		cin >> choice;

		if (choice == "c") {
			break;
		}

		cout << endl;
	}

	cout << "Stopped." << endl;

	current_interface->stopCapture();
}

int main(int argc, char* argv[])
{
	string choice;

	cout <<"  ____  _     _____ _     _       ____  ____  ____  _      _      _____ ____ " << endl
		<< " / ___\\/ \\ /|/  __// \\   / \\     / ___\\/   _\\/  _ \\/ \\  /|/ \\  /|/  __//  __\\ " << endl
		<< " |    \\| |_|||  \\  | |   | |     |    \\|  /  | / \\|| |\\ ||| |\\ |||  \\  |  \\/| " << endl
		<< " \\___ || | |||  /_ | |_/\\| |_/\\  \\___ ||  \\__| |-||| | \\||| | \\|||  /_ |    / " << endl
		<< " \\____/\\_/ \\|\\____ \\____/\\____/  \\____/\\____/\\_/ \\|\\_/  \\|\\_/  \\|\\____ \\_/\\_\\ " << endl;		
	cout << "Welcome to Shell Scanner" << endl << "This program can sniff TCP and HTTP packets and detect shell code on them." << endl
	 << "Input your cmd below (<h> for help)..." << endl << "> ";
	
	while (true) {
		cin >> choice;

		if (choice == "h") {
			printHelp();

		} else if (choice == "q") {
			cout << "Bue..";
			return 0;

		} else if (choice == "v") {
			printAllInterfaces();

		} else if (choice == "s") {
			cin >> choice;
			selected_interface = stoi(choice) - 1;

			if ((selected_interface < 0) || (selected_interface >= interfeces_list.size())) {
				cout << "Interface number is incorrect";
				selected_interface = -1;
			} else {
				cout << "Interface successfully choosen: <<" << interfeces_list[selected_interface]->getIPv4Address() << ">>" << endl;
				startShiffing();
			}

		} else if (choice == "r") {
			
		} else {
			cout << "Command wasn't recognized. Input <h> to view list of all commands";
		}

		cout << endl << "> ";
	}
	return 0;
}