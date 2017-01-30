/*
*  Copyright 2017 by Jiang Wei <jiangwei@jiangwei.org>
*
* This file is part of some open source application.
*
* Some open source application is free software: you can redistribute
* it and/or modify it under the terms of the GNU General Public
* License as published by the Free Software Foundation, either
* version 3 of the License, or (at your option) any later version.
*
* Some open source application is distributed in the hope that it will
* be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
* of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
*
*/


#include <LimeSuite.h>
#include <iostream>
#include <sstream> 
#include <string>
#include <time.h>
#include "BLESDR.hpp"
#include <getopt.h>

#ifdef _WIN32
#include <windows.h>
int gettimeofday(struct timeval *tv, void* ignored) {
	FILETIME ft;
	unsigned __int64 tmp = 0;
	if (NULL != tv) {
		GetSystemTimeAsFileTime(&ft);
		tmp |= ft.dwHighDateTime;
		tmp <<= 32;
		tmp |= ft.dwLowDateTime;
		tmp /= 10;
		tmp -= 11644473600000000Ui64;
		tv->tv_sec = (long)(tmp / 1000000UL);
		tv->tv_usec = (long)(tmp % 1000000UL);
	}
	return 0;
}
#endif



using namespace std;

//Device structure, should be initialize to NULL
lms_device_t* device = NULL;


int error()
{
	//print last error message
	cout << "ERROR:" << LMS_GetLastErrorMessage();
	if (device != NULL)
		LMS_Close(device);
	exit(-1);
}

ble_packet packet;
bool replay = false;
bool sniffer = true;
bool ibeacon = false;
struct timeval tv;
void PacketCallback(ble_packet _packet)
{

	if (sniffer) {
		gettimeofday(&tv, NULL);

		printf("%ld.%06ld ", (long)tv.tv_sec, tv.tv_usec);

		printf(",Address: 0x%08X", _packet.packet_addr);

		printf(",CRC:0x%06X ", _packet.packet_crc);

		printf(",Packet Length:%d\n", _packet.packet_data.size());

		printf("Data:");

		for (int i = 0; i < _packet.packet_data.size(); i++) {

			printf("%02X ", _packet.packet_data[i]);
		}

		printf("\n");

	}

	printf("\n");

	if (replay) {
		packet = _packet;
	}

}

static void usage() {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t[-h] # this help\n");
	fprintf(stderr, "\t[-r RX channel] # RX Channel number. default 39. valid range 0~39.\n");
	fprintf(stderr, "\t[-t TX channel] # TX Channel number. default 39. valid range 0~39.\n");
	fprintf(stderr, "\t[-R Replay mode] # Replay mode. receive packet on RX channel and send packet on TX channel.\n");
	fprintf(stderr, "\t[-S Sniffer mode] # Sniffer mode.default on.\n");
	fprintf(stderr, "\t[-b iBeacon mode] # Send iBeacon packet. example blesdr -b B9407F30F5F8466EAFF925556B57FE6D .\n");
	fprintf(stderr, "\t[-m iBeacon major and minor] # iBeacon Version. default 1.1 example blesdr -m 1.1 .\n");
}

int main(int argc, char *argv[]) {

	int n;
	int tx_chan = 37;
	int rx_chan = 39;
	double v;
	int opt = 0;
	uint8_t uuid[16];
	uint16_t major = 1;
	uint16_t minor = 1;


	while ((opt = getopt(argc, argv, "r:t:b:m:RSh?")) != EOF)
	{
		switch (opt)
		{
		case 'R':
			replay = true;
			break;
		case 'S':
			sniffer = true;
			break;
		case 'r':
			rx_chan = atoi(optarg);
			if (rx_chan > 39 || rx_chan < 0) {
				std::cout << "rx channel valid range 0~39" << endl;;
				exit(0);
			}
			break;
		case 't':
			tx_chan = atoi(optarg);
			if (rx_chan > 39 || rx_chan < 0) {
				std::cout << "tx channel valid range 0~39" << endl;;
				exit(0);
			}
			break;

		case 'b':
			if (strlen(optarg) != 32) {
				std::cout << "UUID must 16 bytes" << endl;;
				exit(0);
			}

			for (int i = 0; i < 16; i++) {
				sscanf(optarg + 2 * i, "%02x", &uuid[i]);
			}
			ibeacon = true;
			break;

		case 'm':
			v = atof(optarg);
			major = (uint16_t)v;
			minor = (uint16_t)((v - major) * 10);
			break;
		case '?':
		case 'h':
			usage();
			return 0;
		}

	}


	BLESDR ble;

	ble.callback = std::function<void(ble_packet)>(&PacketCallback);

	lms_info_str_t list[8]; //should be large enough to hold all detected devices
	if ((n = LMS_GetDeviceList(list)) < 0) //NULL can be passed to only get number of devices
		error();

	cout << "Devices found: " << n << endl; //print number of devices
	if (n < 1)
		return -1;

	//open the first device
	if (LMS_Open(&device, list[0], NULL))
		error();

	//Initialize device with default configuration
	//Do not use if you want to keep existing configuration
	if (LMS_Init(device) != 0)
		error();

	//Enable RX channel
	//Channels are numbered starting at 0
	if (LMS_EnableChannel(device, LMS_CH_TX, 0, true) != 0)
		error();

	if (LMS_EnableChannel(device, LMS_CH_RX, 0, true) != 0)
		error();

	//Automatically selects antenna port
	if (LMS_SetLOFrequency(device, LMS_CH_TX, 0, ble.get_channel_freq(tx_chan)) != 0)
		error();
	if (LMS_SetLOFrequency(device, LMS_CH_RX, 0, ble.get_channel_freq(rx_chan)) != 0)
		error();


	//This set sampling rate for all channels
	if (LMS_SetSampleRate(device, ble.get_sample_rate(), 0) != 0)
		error();

	LMS_SetNormalizedGain(device, LMS_CH_TX, 0, 0.8);

	LMS_SetNormalizedGain(device, LMS_CH_RX, 0, 0.8);

	//Enable test signal generation
	//To receive data from RF, remove this line or change signal to LMS_TESTSIG_NONE
	if (LMS_SetAntenna(device, LMS_CH_TX, 0, 1) != 0)
		error();

	if (LMS_SetAntenna(device, LMS_CH_RX, 0, 2) != 0)
		error();

	//Streaming Setup

	//Initialize stream
	lms_stream_t streamTX; //stream structure
	streamTX.channel = 0; //channel number
	streamTX.fifoSize = 1024 * 128; //fifo size in samples
	streamTX.throughputVsLatency = 1.0; //optimize for max throughput
	streamTX.isTx = true; //RX channel
	streamTX.dataFmt = lms_stream_t::LMS_FMT_F32;
	if (LMS_SetupStream(device, &streamTX) != 0)
		error();

	lms_stream_t streamRX; //stream structure
	streamRX.channel = 0; //channel number
	streamRX.fifoSize = 1024 * 128; //fifo size in samples
	streamRX.throughputVsLatency = 1.0; //optimize for max throughput
	streamRX.isTx = false; //RX channel
	streamRX.dataFmt = lms_stream_t::LMS_FMT_F32;
	if (LMS_SetupStream(device, &streamRX) != 0)
		error();

	//Initialize data buffers

	//Start streaming
	LMS_StartStream(&streamTX);

	LMS_StartStream(&streamRX);

	const int bufersize = 5000;
	float buffer[bufersize * 2];



	std::cout << "rx channel:" << std::dec << rx_chan << endl;
	std::cout << "tx channel:" << std::dec << tx_chan << endl;

	if (ibeacon) {
		std::cout << "iBeacon advertising mode" << endl;

	}
	else if (replay) {

		std::cout << "replay packet mode" << endl;

	}

	if (sniffer) {

		std::cout << "sniffer packet mode" << endl;
	}



	std::vector<float> samples;
	while (true) //run for 5 seconds
	{
		if (ibeacon) {

			samples = ble.sample_for_iBeacon(tx_chan, uuid, major, minor);
		}
		else if(replay){
			samples = ble.sample_for_Packet(37, packet);

		}

		if (ibeacon || replay) {
			LMS_SendStream(&streamTX, samples.data(), samples.size() / 2, NULL, 1000);
		}

		//TODO replay from file//
		if (sniffer || replay) {
			LMS_RecvStream(&streamRX, buffer, bufersize, NULL, 1000);
			ble.Receiver(rx_chan, buffer, bufersize);
		}

	}

	LMS_StopStream(&streamTX); //stream is stopped but can be started again with LMS_StartStream()
	LMS_DestroyStream(device, &streamTX); //stream is deallocated and can no longer be used

	LMS_StopStream(&streamRX); //stream is stopped but can be started again with LMS_StartStream()
	LMS_DestroyStream(device, &streamRX); //stream is deallocated and can no longer be used

										  //Close device
	LMS_Close(device);

	return 0;
}