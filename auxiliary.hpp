//
// Created by kadius on 05.04.23.
//
#pragma once

#include <vector>
#include <iostream>

using BlockVector = std::vector<uint8_t>;
using BlockMatrix = std::vector<std::vector<uint8_t>>;

static BlockVector operator^(BlockVector& lhs, BlockVector& rhs) {
    auto block_sz = lhs.size();
    BlockVector tmp(block_sz, 0);
    for(int i{}; i < block_sz; ++i) {
        tmp[i] = lhs[i]^rhs[i];
    }

    return tmp;
}

void vxor(BlockVector& lhs, BlockVector& rhs, BlockVector& dest) {
    auto block_sz = lhs.size();
//    BlockVector tmp(block_sz, 0);
    for(int i{}; i < block_sz; ++i) {
        dest[i] = lhs[i]^rhs[i];
    }
}

static uint8_t gf_mult(uint8_t a, uint8_t b) {
    uint8_t res{};
    while (b != 0) {
        if (b & 1) {
            res ^= a;
        }

        a = (a << 1) ^ (a&0x80?0xc3: 0x00);

        b >>= 1;
    }
    return res;
}

static
void operator<<=(BlockVector& lhs, size_t n) {
    for(size_t i{}; i < lhs.size()-1; ++i) {
        std::swap(lhs[i], lhs[i+1]);
    }
    lhs.back() = 0;
}


