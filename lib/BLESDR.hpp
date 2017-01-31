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

#pragma once
#include <stdint.h>
#include <vector>
#include <functional>

#define MAX_NUM_PHY_SAMPLE 1520
#define MAX_NUM_CHAR_CMD (256)
#define MAX_NUM_PHY_BYTE (47)
#define SAMPLE_PER_SYMBOL 2  // 
#define LEN_GAUSS_FILTER (4) // pre 2, post 2



#define MAX_LE_SYMBOLS 64

#define LE_ADV_AA 0x8E89BED6

#define ADV_IND			0
#define ADV_DIRECT_IND	1
#define ADV_NONCONN_IND	2
#define SCAN_REQ		3
#define SCAN_RSP		4
#define CONNECT_REQ		5
#define ADV_SCAN_IND	6

struct lell_packet {
	// raw unwhitened bytes of packet, including access address
	uint8_t symbols[MAX_LE_SYMBOLS];

	uint32_t access_address;

	// channel index
	uint8_t channel_idx;
	uint8_t channel_k;

	// number of symbols
	int length;

	uint32_t clk100ns;

	// advertising packet header info
	uint8_t adv_type;
	int adv_tx_add;
	int adv_rx_add;

	unsigned access_address_offenses;
	uint32_t refcount;

	/* flags */
	union {
		struct {
			uint32_t access_address_ok : 1;
		} as_bits;
		uint32_t as_word;
	} flags;
};

class BLESDR {
public:
	BLESDR();
	~BLESDR();

	double get_channel_freq(int channel_number);

	double get_sample_rate() {

		//TODO//
		return 2e6;
	}

	std::function<void(lell_packet)> callback;

	std::vector<float> sample_for_ADV_IND(size_t chan, uint8_t data_type, uint8_t* buff, size_t bufflen);

	std::vector<float> sample_for_RAW(uint8_t* buff, size_t bufflen);

	std::vector<float> sample_for_iBeacon(size_t chan, uint8_t* uuid, uint16_t Major, uint16_t Minor);

	std::vector<float> sample_for_Packet(size_t chan, lell_packet pocket);

	void Receiver(size_t channel, float* samples, size_t samples_len);

private:

	std::vector<float> iqsamples;

	size_t byte_to_bits(uint8_t* byte, size_t len, char* bits);

	float* generate_gaussian_taps(unsigned samples_per_sym, unsigned L, double bt);

	void btle_calc_crc(void* src, uint8_t len, uint8_t* dst);

	void btle_whiten(uint8_t chan, uint8_t* buf, uint8_t len);

#define chunk(x,y) ((btle_pdu_chunk*)(x.payload+y))

	struct btle_pdu_chunk {
		uint8_t size;
		uint8_t type;
		uint8_t data[];
	};

	struct btle_adv_pdu {

		// packet header
		uint8_t pdu_type; // PDU type
		uint8_t pl_size;  // payload size

						  // MAC address
		uint8_t mac[6];

		// payload (including 3 bytes for CRC)
		uint8_t payload[42];
	};

	int gen_sample_from_phy_bit(char *bit, float *sample, int num_bit);
	float tmp_phy_bit_over_sampling[MAX_NUM_PHY_SAMPLE + 2 * LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL];
	float tmp_phy_bit_over_sampling1[MAX_NUM_PHY_SAMPLE];
	float * gauss_coef;






	uint8_t chan;
	int32_t g_threshold; // Quantization threshold
	int g_srate; // sample rate downconvert ratio
	int32_t samples;
	int skipSamples;
	int srate;
	double last_phase;

	int rb_head = -1;
	int16_t *rb_buf;
	/* Init Ring Buffer */
	void RB_init(void);
	/* increment Ring Buffer Head */
	void RB_inc(void);
	/* Access Ring Buffer location l */

	uint8_t SwapBits(uint8_t a);

	bool Quantize(int16_t l);

	int32_t ExtractThreshold(void);

	bool DetectPreamble(void);

	uint8_t inline ExtractByte(int l);

	void ExtractBytes(int l, uint8_t* buffer, int count);

	bool feedOne(const uint16_t sample);

	bool DecodePacket(int32_t sample, int srate);

	bool DecodeBTLEPacket(int32_t sample, int srate);

	void btle_reverse_whiten(uint8_t chan,uint8_t* data, uint8_t len);

	uint32_t btle_reverse_crc(const uint8_t* data, uint8_t len, uint8_t* dst);

};