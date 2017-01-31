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

lell_packet packet;
bool replay = false;
bool sniffer = true;
bool ibeacon = false;
struct timeval tv;



static void _dump_uuid(const uint8_t *uuid) {
	int i;
	for (i = 0; i < 4; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 4; i < 6; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 6; i < 8; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 8; i < 10; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 10; i < 16; ++i)
		printf("%02x", uuid[i]);
}


static const char *ADV_TYPE_NAMES[] = {
	"ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", "SCAN_REQ",
	"SCAN_RSP", "CONNECT_REQ", "ADV_SCAN_IND",
};

static const char *CONNECT_SCA[] = {
	"251 ppm to 500 ppm", "151 ppm to 250 ppm", "101 ppm to 150 ppm",
	"76 ppm to 100 ppm", "51 ppm to 75 ppm", "31 ppm to 50 ppm",
	"21 ppm to 30 ppm", "0 ppm to 20 ppm",
};

/* flags */
static const char *FLAGS[] = {
	"LE Limited Discoverable Mode", "LE General Discoverable Mode",
	"BR/EDR Not Supported",
	"Simultaneous LE and BR/EDR to Same Device Capable (Controller)",
	"Simultaneous LE and BR/EDR to Same Device Capable (Host)",
	"Reserved", "Reserved", "Reserved",
};


#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

const char * lell_get_adv_type_str(const lell_packet *pkt)
{

	if (pkt->adv_type < COUNT_OF(ADV_TYPE_NAMES))
		return ADV_TYPE_NAMES[pkt->adv_type];
	return "UNKNOWN";
}

static void _dump_addr(const char *name, const uint8_t *buf, int offset, int random) {
	int i;
	printf("    %s%02x", name, buf[offset + 5]);
	for (i = 4; i >= 0; --i)
		printf(":%02x", buf[offset + i]);
	printf(" (%s)\n", random ? "random" : "public");
}

static void _dump_8(const char *name, const uint8_t *buf, int offset) {
	printf("    %s%02x (%d)\n", name, buf[offset], buf[offset]);
}

static void _dump_16(const char *name, const uint8_t *buf, int offset) {
	uint16_t val = buf[offset + 1] << 8 | buf[offset];
	printf("    %s%04x (%d)\n", name, val, val);
}

static void _dump_24(char *name, const uint8_t *buf, int offset) {
	uint32_t val = buf[offset + 2] << 16 | buf[offset + 1] << 8 | buf[offset];
	printf("    %s%06x\n", name, val);
}

static void _dump_32(const char *name, const uint8_t *buf, int offset) {
	uint32_t val = buf[offset + 3] << 24 |
		buf[offset + 2] << 16 |
		buf[offset + 1] << 8 |
		buf[offset + 0];
	printf("    %s%08x\n", name, val);
}

// Refer to pg 1735 of Bluetooth Core Spec 4.0
static void _dump_scan_rsp_data(const uint8_t *buf, int len) {
	int pos = 0;
	int sublen, i;
	uint8_t type;
	uint16_t val;
	char *cval;

	while (pos < len) {
		sublen = buf[pos];
		++pos;
		if (pos + sublen > len) {
			printf("Error: attempt to read past end of buffer (%d + %d > %d)\n", pos, sublen, len);
			return;
		}
		if (sublen == 0) {
			printf("Early return due to 0 length\n");
			return;
		}
		type = buf[pos];
		printf("        Type %02x", type);
		switch (type) {
		case 0x01:
			printf(" (Flags)\n");
			printf("           ");
			for (i = 0; i < 8; ++i)
				printf("%d", buf[pos + 1] & (1 << (7 - i)) ? 1 : 0);
			printf("\n");
			for (i = 0; i < 8; ++i) {
				if (buf[pos + 1] & (1 << i)) {
					printf("               ");
					printf("%s\n", FLAGS[i]);
				}
			}
			printf("\n");
			break;
		case 0x02:
			printf(" (16-bit Service UUIDs, more available)\n");
			goto print16;
		case 0x03:
			printf(" (16-bit Service UUIDs) \n");
		print16:
			if ((sublen - 1) % 2 == 0) {
				for (i = 0; i < sublen - 1; i += 2) {
					uint16_t *uuid = (uint16_t *)&buf[pos + 1 + i];
					printf("           %04x\n", *uuid);
				}
			}
			break;
		case 0x06:
			printf(" (128-bit Service UUIDs, more available)\n");
			goto print128;
		case 0x07:
			printf(" (128-bit Service UUIDs)\n");
		print128:
			if ((sublen - 1) % 16 == 0) {
				uint8_t uuid[16];
				for (i = 0; i < sublen - 1; ++i) {
					uuid[15 - (i % 16)] = buf[pos + 1 + i];
					if ((i & 15) == 15) {
						printf("           ");
						_dump_uuid(uuid);
						printf("\n");
					}
				}
			}
			else {
				printf("Wrong length (%d, must be divisible by 16)\n", sublen - 1);
			}
			break;
		case 0x09:
			printf(" (Complete Local Name)\n");
			printf("           ");
			for (i = 1; i < sublen; ++i)
				printf("%c", isprint(buf[pos + i]) ? buf[pos + i] : '.');
			printf("\n");
			break;
		case 0x0a:
			printf(" (Tx Power Level)\n");
			printf("           ");
			if (sublen - 1 == 1) {
				cval = (char *)&buf[pos + 1];
				printf("%d dBm\n", *cval);
			}
			else {
				printf("Wrong length (%d, should be 1)\n", sublen - 1);
			}
			break;
		case 0x12:
			printf(" (Slave Connection Interval Range)\n");
			printf("           ");
			if (sublen - 1 == 4) {
				val = (buf[pos + 2] << 8) | buf[pos + 1];
				printf("(%0.2f, ", val * 1.25);
				val = (buf[pos + 4] << 8) | buf[pos + 3];
				printf("%0.2f) ms\n", val * 1.25);
			}
			else {
				printf("Wrong length (%d, should be 4)\n", sublen - 1);
			}
			break;
		case 0x16:
			printf(" (Service Data)\n");
			printf("           ");
			if (sublen - 1 >= 2) {
				val = (buf[pos + 2] << 8) | buf[pos + 1];
				printf("UUID: %02x", val);
				if (sublen - 1 > 2) {
					printf(", Additional:");
					for (i = 3; i < sublen; ++i)
						printf(" %02x", buf[pos + i]);
				}
				printf("\n");
			}
			else {
				printf("Wrong length (%d, should be >= 2)\n", sublen - 1);
			}
			break;
		case 0xff:
			break;
		default:
			printf("\n");
			printf("           ");
			for (i = 1; i < sublen; ++i)
				printf(" %02x", buf[pos + i]);
			printf("\n");
		}
		pos += sublen;
	}
}

void lell_print(const lell_packet *pkt) {

	int i;
	if (false) {

		//TODO//

	}
	else {
		printf("Advertising / AA %08x (%s)/ %2d bytes\n", pkt->access_address,
			pkt->flags.as_bits.access_address_ok ? "valid" : "invalid",
			pkt->length);
		printf("    Channel Index: %d\n", pkt->channel_idx);
		printf("    Type:  %s\n", lell_get_adv_type_str(pkt));

		switch (pkt->adv_type) {
		case ADV_IND:
		case ADV_NONCONN_IND:
		case ADV_SCAN_IND:
			_dump_addr("AdvA:  ", pkt->symbols, 6, pkt->adv_tx_add);
			if (pkt->length - 6 > 0) {
				printf("    AdvData:");
				for (i = 0; i < pkt->length - 6; ++i)
					printf(" %02x", pkt->symbols[12 + i]);
				printf("\n");
				_dump_scan_rsp_data(&pkt->symbols[12], pkt->length - 6);
			}
			break;
		case ADV_DIRECT_IND:
			_dump_addr("AdvA:  ", pkt->symbols, 6, pkt->adv_tx_add);
			_dump_addr("InitA: ", pkt->symbols, 12, pkt->adv_rx_add);
			break;
		case SCAN_REQ:
			_dump_addr("ScanA: ", pkt->symbols, 6, pkt->adv_tx_add);
			_dump_addr("AdvA:  ", pkt->symbols, 12, pkt->adv_rx_add);
			break;
		case SCAN_RSP:
			_dump_addr("AdvA:  ", pkt->symbols, 6, pkt->adv_tx_add);
			printf("    ScanRspData:");
			for (i = 0; i < pkt->length - 6; ++i)
				printf(" %02x", pkt->symbols[12 + i]);
			printf("\n");
			_dump_scan_rsp_data(&pkt->symbols[12], pkt->length - 6);
			break;
		case CONNECT_REQ:
			_dump_addr("InitA: ", pkt->symbols, 6, pkt->adv_tx_add);
			_dump_addr("AdvA:  ", pkt->symbols, 12, pkt->adv_rx_add);
			_dump_32("AA:    ", pkt->symbols, 18);
			_dump_24("CRCInit: ", pkt->symbols, 22);
			_dump_8("WinSize: ", pkt->symbols, 25);
			_dump_16("WinOffset: ", pkt->symbols, 26);
			_dump_16("Interval: ", pkt->symbols, 28);
			_dump_16("Latency: ", pkt->symbols, 30);
			_dump_16("Timeout: ", pkt->symbols, 32);

			printf("    ChM:");
			for (i = 0; i < 5; ++i)
				printf(" %02x", pkt->symbols[34 + i]);
			printf("\n");

			printf("    Hop: %d\n", pkt->symbols[39] & 0x1f);
			printf("    SCA: %d, %s\n",
				pkt->symbols[39] >> 5,
				CONNECT_SCA[pkt->symbols[39] >> 5]);
			break;
		}



	}


	printf("\n");
	printf("    Data: ");
	for (i = 6; i < 6 + pkt->length; ++i)
		printf(" %02x", pkt->symbols[i]);
	printf("\n");

	printf("    CRC:  ");
	for (i = 0; i < 3; ++i)
		printf(" %02x", pkt->symbols[6 + pkt->length + i]);
	printf("\n");

}



void PacketCallback(lell_packet _packet)
{

	if (sniffer) {

		lell_print(&_packet);

		printf("\n");

	}


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

	ble.callback = std::function<void(lell_packet)>(&PacketCallback);

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
		else if (replay) {

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