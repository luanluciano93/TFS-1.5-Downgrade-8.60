// Copyright 2022 The Forgotten Server Authors. All rights reserved.
// Use of this source code is governed by the GPL-2.0 License that can be found in the LICENSE file.

#include "otpch.h"

#include "xtea.h"

#include <array>
#include <assert.h>

namespace xtea {

namespace {

constexpr uint32_t delta = 0x9E3779B9;

template<typename Round>
void apply_rounds(uint8_t* data, size_t length, Round round)
{
	for (auto j = 0u; j < length; j += 8) {
		uint32_t left = data[j+0] | data[j+1] << 8u | data[j+2] << 16u | data[j+3] << 24u,
				right = data[j+4] | data[j+5] << 8u | data[j+6] << 16u | data[j+7] << 24u;

		round(left, right);

		data[j] = static_cast<uint8_t>(left);
		data[j+1] = static_cast<uint8_t>(left >> 8u);
		data[j+2] = static_cast<uint8_t>(left >> 16u);
		data[j+3] = static_cast<uint8_t>(left >> 24u);
		data[j+4] = static_cast<uint8_t>(right);
		data[j+5] = static_cast<uint8_t>(right >> 8u);
		data[j+6] = static_cast<uint8_t>(right >> 16u);
		data[j+7] = static_cast<uint8_t>(right >> 24u);
	}
}

}

round_keys expand_key(const key& k)
{
	round_keys expanded;

	for (uint32_t i = 0, sum = 0, next_sum = sum + delta; i < expanded.size(); i += 2, sum = next_sum, next_sum += delta) {
		expanded[i] = sum + k[sum & 3];
		expanded[i + 1] = next_sum + k[(next_sum >> 11) & 3];
	}

	return expanded;
}

void encrypt(uint8_t* data, size_t length, const round_keys& k)
{
	for (int32_t i = 0; i < k.size(); i += 2) {
		apply_rounds(data, length, [&](uint32_t& left, uint32_t& right) {
			left += ((right << 4 ^ right >> 5) + right) ^ k[i];
			right += ((left << 4 ^ left >> 5) + left) ^ k[i + 1];
		});
	};
}

void decrypt(uint8_t* data, size_t length, const round_keys& k)
{
	for (int32_t i = k.size() - 1; i > 0; i -= 2) {
		apply_rounds(data, length, [&](uint32_t& left, uint32_t& right) {
			right -= ((left << 4 ^ left >> 5) + left) ^ k[i];
			left -= ((right << 4 ^ right >> 5) + right) ^ k[i - 1];
		});
	};
}

} // namespace xtea
