/**
 *  Copyright 2017 by Jiang Wei <jiangwei@jiangwei.org>
 *  Copyright 2015 by Xianjun Jiao (putaoshu@gmail.com)
 *  Copyright (C) 2013 Florian Echtler <floe@butterbrot.org>
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



#include "BLESDR.hpp"
#include <iostream>
#include <complex>
#define _USE_MATH_DEFINES
#include <math.h>
#include <inttypes.h>


BLESDR::BLESDR() :
	samples(0),
	chan(37),
	skipSamples(50),
	srate(2)
{
	RB_init();
	gauss_coef = generate_gaussian_taps(SAMPLE_PER_SYMBOL, LEN_GAUSS_FILTER, 0.5);
}

BLESDR::~BLESDR() {

	delete gauss_coef;
}

size_t BLESDR::byte_to_bits(uint8_t* byte, size_t len, char* bits) {

	for (int j = 0; j < len; j++) {
		for (int i = 0; i < 8; i++) {
			// Mask each bit in the byte and store it
			bits[j * 8 + i] = (byte[j] >> i) & 1;
		}
	}
	return len * 8;
}

void BLESDR::Encrc(void* src, uint8_t len, uint8_t* dst) {

	uint8_t* buf = (uint8_t*)src;

	// initialize 24-bit shift register in "wire bit order"
	// dst[0] = bits 23-16, dst[1] = bits 15-8, dst[2] = bits 7-0
	dst[0] = 0xAA;
	dst[1] = 0xAA;
	dst[2] = 0xAA;

	while (len--) {

		uint8_t d = *(buf++);

		for (uint8_t i = 1; i; i <<= 1, d >>= 1) {

			// save bit 23 (highest-value), left-shift the entire register by one
			uint8_t t = dst[0] & 0x01;         dst[0] >>= 1;
			if (dst[1] & 0x01) dst[0] |= 0x80; dst[1] >>= 1;
			if (dst[2] & 0x01) dst[1] |= 0x80; dst[2] >>= 1;

			// if the bit just shifted out (former bit 23) and the incoming data
			// bit are not equal (i.e. bit_out ^ bit_in == 1) => toggle tap bits
			if (t != (d & 1)) {
				// toggle register tap bits (=XOR with 1) according to CRC polynom
				dst[2] ^= 0xDA; // 0b11011010 inv. = 0b01011011 ^= x^6+x^4+x^3+x+1
				dst[1] ^= 0x60; // 0b01100000 inv. = 0b00000110 ^= x^10+x^9
			}
		}
	}
}

void BLESDR::whiten(uint8_t chan, uint8_t* buf, uint8_t len) {

	// initialize LFSR with current channel, set bit 6
	uint8_t lfsr = chan | 0x40;

	while (len--) {
		uint8_t res = 0;
		// LFSR in "wire bit order"
		for (uint8_t i = 1; i; i <<= 1) {
			if (lfsr & 0x01) {
				lfsr ^= 0x88;
				res |= i;
			}
			lfsr >>= 1;
		}
		*(buf++) ^= res;
	}


}

double BLESDR::get_channel_freq(int channel_number) {

	double freq_hz;
	if (channel_number == 37) {
		freq_hz = 2402000000;
	}
	else if (channel_number == 38) {
		freq_hz = 2426000000;
	}
	else if (channel_number == 39) {
		freq_hz = 2480000000;
	}
	else if (channel_number >= 0 && channel_number <= 10) {
		freq_hz = 2404000000 + channel_number * 2000000;
	}
	else if (channel_number >= 11 && channel_number <= 36) {
		freq_hz = 2428000000 + (channel_number - 11) * 2000000;
	}
	else {
		freq_hz = 0;
	}
	return(freq_hz);

}

#define month(m) month_lookup[ (( ((( (m[0] % 24) * 13) + m[1]) % 24) * 13) + m[2]) % 24 ]
const uint8_t month_lookup[24] = { 0,6,0,4,0,1,0,17,0,8,0,0,3,0,0,0,18,2,16,5,9,0,1,7 };

std::vector<float> BLESDR::sample_for_ADV_IND(size_t chan, uint8_t data_type, uint8_t* buff, size_t buflen) {
	btle_adv_pdu pdu;

	uint8_t pls = 0;
	uint8_t preamble = 0xAA;

	const uint32_t access_address = 0x8E89BED6;

	// insert pseudo-random MAC address
	pdu.mac[0] = ((__TIME__[6] - 0x30) << 4) | (__TIME__[7] - 0x30);
	pdu.mac[1] = ((__TIME__[3] - 0x30) << 4) | (__TIME__[4] - 0x30);
	pdu.mac[2] = ((__TIME__[0] - 0x30) << 4) | (__TIME__[1] - 0x30);
	pdu.mac[3] = ((__DATE__[4] - 0x30) << 4) | (__DATE__[5] - 0x30);
	pdu.mac[4] = month(__DATE__);
	pdu.mac[5] = ((__DATE__[9] - 0x30) << 4) | (__DATE__[10] - 0x30) | 0xC0;// static random address should have two topmost bits set

	chunk(pdu, pls)->size = 0x02;  // chunk size: 2
	chunk(pdu, pls)->type = 0x01;  // chunk type: device flags
	chunk(pdu, pls)->data[0] = 0x1A;  // flags: LE-only, limited discovery mode
	pls += 3;

	// add custom data, if applicable
	if (buflen > 0) {
		chunk(pdu, pls)->size = buflen + 1;  // chunk size
		chunk(pdu, pls)->type = data_type; // chunk type
		for (uint8_t i = 0; i < buflen; i++)
			chunk(pdu, pls)->data[i] = ((uint8_t*)buff)[i];
		pls += buflen + 2;
	}

	// assemble header
	pdu.pdu_type = 0x40;
	pdu.pl_size = pls + 6;

	// calculate CRC over header+MAC+payload, append after payload
	uint8_t* outbuf = (uint8_t*)&pdu;

	Encrc(&pdu, pls + 8, outbuf + pls + 8);

	whiten(chan, outbuf, pls + 11);

	size_t numbits = (pls + 11 + 5) * 8;
	int offset = 0;
	char * bits = new char[numbits];

	iqsamples.resize((numbits*SAMPLE_PER_SYMBOL + (LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL)) * 2);

	offset = byte_to_bits(&preamble, 1, bits);

	offset += byte_to_bits((uint8_t*)&access_address, 4, bits + offset);

	offset += byte_to_bits(outbuf, pls + 11, bits + offset);

	int num_phy_sample = gen_sample_from_phy_bit(bits, iqsamples.data(), numbits);

	delete bits;

	return iqsamples;
}

int BLESDR::gen_sample_from_phy_bit(char *bit, float *sample, int num_bit) {
	int num_sample = (num_bit*SAMPLE_PER_SYMBOL) + (LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL);
	int i, j;
	for (i = 0; i < (LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL - 1); i++) {
		tmp_phy_bit_over_sampling[i] = 0.0;
	}
	for (i = (LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL - 1 + num_bit*SAMPLE_PER_SYMBOL); i < (2 * LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL - 2 + num_bit*SAMPLE_PER_SYMBOL); i++) {
		tmp_phy_bit_over_sampling[i] = 0.0;
	}
	for (i = 0; i < (num_bit*SAMPLE_PER_SYMBOL); i++) {
		if (i%SAMPLE_PER_SYMBOL == 0) {
			tmp_phy_bit_over_sampling[i + (LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL - 1)] = (float)(bit[i / SAMPLE_PER_SYMBOL]) * 2.0 - 1.0;
		}
		else {
			tmp_phy_bit_over_sampling[i + (LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL - 1)] = 0.0;
		}
	}
	int len_conv_result = num_sample - 1;
	for (i = 0; i < len_conv_result; i++) {
		float acc = 0;
		for (j = 0; j < (LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL); j++) {
			acc = acc + gauss_coef[(LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL) - j - 1] * tmp_phy_bit_over_sampling[i + j];
		}
		tmp_phy_bit_over_sampling1[i] = acc;
	}
	float tmp = 0;
	sample[0] = cosf(tmp);
	sample[1] = sinf(tmp);
	for (i = 1; i < num_sample; i++) {
		tmp = tmp + (M_PI*0.5)*tmp_phy_bit_over_sampling1[i - 1] / ((float)SAMPLE_PER_SYMBOL);
		sample[i * 2 + 0] = cos(tmp);
		sample[i * 2 + 1] = sin(tmp);
	}
	return(num_sample);
}

float* BLESDR::generate_gaussian_taps(unsigned samples_per_sym, unsigned L, double bt) {

	float* taps = new float[L*samples_per_sym];
	double scale = 0;
	double dt = 1.0 / samples_per_sym;
	double s = 1.0 / (sqrt(log(2.0)) / (2 * M_PI*bt));
	double t0 = -0.5 * L*samples_per_sym;
	double ts;
	for (unsigned i = 0; i < L*samples_per_sym; i++) {
		t0++;
		ts = s*dt*t0;
		taps[i] = exp(-0.5*ts*ts);
		scale += taps[i];
	}
	for (unsigned i = 0; i < L*samples_per_sym; i++)
		taps[i] = taps[i] / scale;

	return taps;


}

std::vector<float> BLESDR::sample_for_iBeacon(size_t chan, uint8_t* uuid, uint16_t Major, uint16_t Minor) {

	uint8_t buffer[25] = { 0x4C ,0x00,0x02 ,0x15 };

	if (sizeof(uuid) != 16)
		std::runtime_error("UUID size must 16 ");

	for (int i = 0; i < 16; i++) {
		buffer[i + 4] = uuid[i];
	}

	buffer[20] = Major >> 8;
	buffer[21] = Major & 0xFF;

	buffer[22] = Minor >> 8;
	buffer[23] = Minor & 0xFF;

	buffer[24] = 0xC5;

	return this->sample_for_ADV_IND(chan, 0xFF, buffer, sizeof(buffer));


}

std::vector<float> BLESDR::sample_for_RAW(size_t chan, uint8_t* buff, size_t bufflen) {

	size_t numbits = (bufflen) * 8;
	char * bits = new char[numbits];

	byte_to_bits(buff, bufflen, bits);

	int num_phy_sample = gen_sample_from_phy_bit(bits, iqsamples.data(), numbits);

	delete bits;

	return iqsamples;
}

std::vector<float> BLESDR::sample_for_Packet(size_t chan, ble_packet pocket) {

	std::vector<uint8_t> buff;

	for (size_t i = 0; i < pocket.packet_data.size(); i++)
	{
		buff.push_back(pocket.packet_data[i]);
	}

	buff.push_back(SwapBits(pocket.packet_crc >> 16));

	buff.push_back(SwapBits(pocket.packet_crc >> 8));

	buff.push_back(SwapBits(pocket.packet_crc));

	uint8_t* outbuf = (uint8_t*)buff.data();

	whiten(chan, outbuf, buff.size());

	size_t numbits = (buff.size() + 5) * 8;
	int offset = 0;
	char * bits = new char[numbits];

	iqsamples.resize((numbits*SAMPLE_PER_SYMBOL + (LEN_GAUSS_FILTER*SAMPLE_PER_SYMBOL)) * 2);

	offset = byte_to_bits(&pocket.packet_preamble, 1, bits);

	offset += byte_to_bits((uint8_t*)&pocket.packet_addr, 4, bits + offset);

	offset += byte_to_bits(outbuf, buff.size(), bits + offset);

	int num_phy_sample = gen_sample_from_phy_bit(bits, iqsamples.data(), numbits);

	delete bits;

	return iqsamples;

}