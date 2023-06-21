#include "sniffer.h"
#include <fstream>
#include <shlwapi.h>
#include <thread>

#pragma comment (lib, "Shlwapi.lib")

void waitUserInput(Sniffer * sniffer);
std::string GetCurrDirectory();

int main(int argc, char* argv[]) {
	if (argc < 3) {
		std::cout << "Too few input arguments\n";
		return 1;
	}

	bool good = true;

	std::string ipStr = argv[1];

	std::string logFileName = argv[2];

	std::ofstream outputFile;

	outputFile.open(logFileName);

	if (outputFile.is_open())
	{
		Sniffer sniffer(ipStr, outputFile);

		if (sniffer.hasError() == false) {

			std::cout << "Press ENTER to stop sniffer...\n";

			std::thread thread(waitUserInput, &sniffer);

			sniffer.process();

			thread.join();
		}
		else {
			good = false;
		}
	}
	else {
		std::cout << "Error opening file\n";

		good = false;
	}

	outputFile.close();

	if (good) {
		std::string outputFilePath = logFileName;

		if (PathIsRelativeA(logFileName.c_str())) {
			outputFilePath = GetCurrDirectory() + "\\" + logFileName;
		}

		std::cout << "Sniffer stopped...\n";
		std::cout << "Output file can be finded here: " << outputFilePath << "\n";
	}
}

void waitUserInput(Sniffer * sniffer)
{
	std::string str;

	while (std::getline(std::cin, str)) {
		if (str == "") {
			sniffer->stop();
			std::cout << "wait...\n";
			break;
		}
	}
}

std::string GetCurrDirectory() {
	char path[MAX_PATH];
	ZeroMemory(path, MAX_PATH);
	GetCurrentDirectoryA(sizeof(path), path);

	return std::string(path);
}



