//
// Created by kadius on 04.04.23.
//

#ifndef TESTPROJECT_LSX_HPP
#define TESTPROJECT_LSX_HPP

#pragma once
#include <iomanip>
#include <vector>
#include <iostream>
#include <iterator>
#include <fstream>

#include "crc.hpp"




namespace cipher {

    using BlockVector = std::vector<uint8_t>;
    using BlockMatrix = std::vector<std::vector<uint8_t>>;

    static
    auto
    operator^(BlockVector& lhs, BlockVector& rhs)
    ->BlockVector
    {
        auto block_sz = lhs.size();
        BlockVector tmp(block_sz, 0);
        for(int i{}; i < block_sz; ++i) {
            tmp[i] = lhs[i]^rhs[i];
        }

        return tmp;
    }

    static
    void
    operator^=(BlockVector& lhs, const BlockVector& rhs)
    {
        for(int i{}; i < lhs.size(); ++i) {
             lhs[i] ^= rhs[i];
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

        bool msb = lhs[15] & 0x80;
        lhs[0] <<= 1;

        for(int i{1}; i < 16; ++i) {
            bool cur_msb = lhs[i] & 0x80;
            lhs[i] <<= 1;
            lhs[i] |= msb;
            msb = cur_msb;
        }

    }

class LSX;
LSX& X_impl(LSX& cipher, const BlockVector& key);
void X_impl_2(LSX& cipher, BlockVector& state, const BlockVector& key);
LSX& S_impl_1(LSX& cipher);
void S_impl_2(LSX& cipher, BlockVector& state);
LSX& R_impl_1(LSX& cipher);
LSX& R_impl_2(LSX& cipher, BlockVector& state);

class LSX {
    friend LSX& X_impl(LSX& cipher, const BlockVector& key);
    friend void X_impl_2(LSX& cipher, BlockVector& state, const BlockVector& key);
    friend LSX& S_impl_1(LSX& cipher);
    friend void S_impl_2(LSX& cipher, BlockVector& state);
    friend LSX& R_impl_1(LSX& cipher);
    friend LSX& R_impl_2(LSX& cipher, BlockVector& state);

private:
    void time_stamp() {
        time_t result = time(NULL);
        if(result != (time_t)(-1))
            log << asctime(gmtime(&result));
    }

    std::ofstream log;

    size_t state_size_{16};
    uint8_t poly{0xc3};

    BlockVector sbox_ = {0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB,
                         0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D, 0xE9, 0x77, 0xF0, 0xDB, 0x93,
                         0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1, 0xF9,
                         0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B,
                         0x01, 0x8E, 0x4F, 0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06,
                         0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F, 0xEB, 0x34, 0x2C, 0x51, 0xEA,
                         0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC, 0xB5,
                         0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C,
                         0xB7, 0x5D, 0x87, 0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3,
                         0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1, 0x32, 0x75, 0x19, 0x3D, 0xFF,
                         0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57, 0xDF,
                         0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C,
                         0x22, 0xB9, 0x03, 0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC,
                         0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A, 0xA7, 0x97, 0x60, 0x73, 0x1E,
                         0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41, 0xAD,
                         0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69,
                         0xD5, 0x95, 0x3B, 0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30,
                         0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89, 0xE1, 0x1B, 0x83, 0x49, 0x4C,
                         0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61, 0x20,
                         0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE,
                         0xE5, 0x6C, 0x52, 0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1,
                         0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6};

    BlockVector lvec_ = {0x01, 0x94, 0x20, 0x85, 0x10, 0xc2, 0xc0, 0x01, 0xfb, 0x01, 0xc0, 0xc2, 0x10, 0x85, 0x20, 0x94};

    BlockMatrix round_constants_;

    BlockVector state_;//the block to which the LSX transformations are gonna be applied to.
    BlockVector master_key_;
    BlockMatrix keys_;//key schedule

public:

    template<typename Vector>
    LSX(Vector&& master_key) : master_key_(std::forward<Vector>(master_key)) {
        log = std::ofstream("lsxlog.txt", std::ios_base::app);


        //checksums
        auto fn_ptr = &X_impl;
        auto ptr = (uint8_t*)(fn_ptr);
        uint8_t func[111];
        for (size_t i{}; i < 111; ++i) {
            func[i] = ptr[i];
        }

        Crc32 crc32;
        crc32.input(func);

        size_t res = crc32.result();

        if(res != 3673647497) {
            std::cout << "FUCK OFF, INTRUDER!" << std::endl;
            time_stamp();
            log << "INTRUDER DETECTED" << std::endl;
//            exit(2);
        }

        initialize_round_constants();
        master_key_ = BlockVector{0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88};
        state_ = BlockVector{0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
        key_schedule();
        E();
        BlockVector test_case = {0x7f,0x67,0x9d,0x90,0xbe,0xbc,0x24,0x30,0x5a,0x46,0x8d,0x42,0xb9,0xd4,0xed,0xcd};
        for(size_t i{}; i < 16; ++i) {
            if(state_[i] != test_case[15-i]) {
                std::cout << "PROGRAM HAS BEEN COMPROMISED!";
                time_stamp();
                log << ("...from cipher class constructor->") << this;
                log << "PROGRAM HAS BEEN COMPROMISED!" << std::endl;
            }
        }

        state_.clear();
        key_schedule();
    }

    template<typename Vector>
    LSX(Vector&& state, Vector&& master_key) {
        //check checksums

        initialize_round_constants();
        master_key_ = BlockVector{0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88};
        state = BlockVector{0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
        key_schedule();
        E();
        BlockVector test_case = {0x7a,0x67,0x9d,0x90,0xbe,0xbc,0x24,0x30,0x5a,0x46,0x8d,0x42,0xb9,0xd4,0xed,0xcd};
        for(size_t i{}; i < 16; ++i) {
            if(state_[i] != test_case[i]) {
                std::cout << "PROGRAM HAS BEEN COMPROMISED!" << std::endl;
                time_stamp();
                log << ("...from cipher class constructor->") << this;
                log << "PROGRAM HAS BEEN COMPROMISED!" << std::endl;
            }
        }


        state_ = std::forward<Vector>(state);
        master_key_ = std::forward<Vector>(master_key);

        key_schedule();
    }

    ~LSX() {
        for(auto& k: master_key_) {
            k &= 0x00;
        }

        for(auto& k: master_key_) {
            if (k != 0x00) {
                std::cout << "THE KEY HAS BEEN COMPROMISED!" << std::endl;
                time_stamp();
                log << ("...from cipher class destructor->") << this;
                log << "THE KEY HAS BEEN COMPROMISED!" << std::endl;
            }
        }

        for(auto& vec: keys_) {
            for(auto& k: vec) {
                k &= 0x00;
            }
        }

        for(auto& vec: keys_) {
            for(auto& k: vec) {
                if(k != 0x00) {
                    std::cout << "THE KEY SCHEDULE HAS BEEN COMPROMISED!" << std::endl;
                    time_stamp();
                    log << ("...from cipher class destructor->") << this;
                    log << "THE KEY SCHEDULE HAS BEEN COMPROMISED!" << std::endl;
                }
            }
        }
    }

    void initialize_round_constants() {
        for(uint8_t i{1}; i <= 32; ++i) {
            BlockVector tmp(16, 0);
            tmp[0] = i;

            L(tmp);

            round_constants_.emplace_back(std::move(tmp));
        }
    }

    LSX& X(const BlockVector& key);
    void X(BlockVector& state, const BlockVector& key);

    LSX& R();
    LSX& R(BlockVector& state);

    LSX& S();
    void S(BlockVector& state);


    LSX& L();
    LSX& L(BlockVector& state);

    BlockVector
    F(const BlockVector& Ki, const BlockVector& C);

    void
    key_schedule();

    void E();
    void E(BlockVector&& msg);

    void show() {
        for(auto it = state_.rbegin(); it != state_.rend(); ++it) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)(*it);
        }
    }

    void
    set_state(BlockVector&& state) {
        state_ = std::move(state);
    }

    BlockVector
    get_state() {
        return state_;
    }
};

//    static
//    BlockVector
//    OMAC(size_t s, const uint8_t* const message, size_t msg_length, BlockVector&& key) {
//
//        std::vector<uint8_t> B(128, 0);
//        B[120] = 1;
//        B[125] = 1;
//        B[126] = 1;
//        B[127] = 1;
//
//        LSX cipher(std::vector<uint8_t>(128,0), std::move(key));
//        cipher.E();
//        auto R = cipher.get_state();
//
//
//        BlockVector K1, K2;
//        if(R.back() & 0x80) {
//            R <<= 1;
//            K1 = std::move(R);
//            K1 ^= B;
//        } else {
//            R <<= 1;
//            K1 = std::move(R);
//        }
//
//        auto tmpK1 = K1;
//
//        if(K1.back() & 0x80) {
//            tmpK1 <<= 1;
//            K2 = std::move(tmpK1);
//            K2 ^= B;
//        } else {
//            tmpK1 <<= 1;
//            K2 = std::move(tmpK1);
//        }
//
//        std::vector<uint8_t> C0(128, 0);
//        cipher.set_state(std::move(C0));
////        LSX cipher{std::move(C0),std::move(key)};
//
//        size_t num = msg_length/128;
//        size_t incomplete = msg_length%128;
//
//        std::vector<std::vector<uint8_t>> messages(num, std::vector<uint8_t>(128, 0));
//
//        for(size_t i{}; i < num; ++i) {
//            for(size_t j{}; j < 128; ++j) {
//                messages[i][j] = message[i*128+j];
//            }
//        }
//
//        if(incomplete == 0) {
//
//            for(size_t i{}; i < num-1; ++i) {
//                cipher.X(messages[i]).E();
//            }
//
//            cipher.X(messages[num-1]).X(K1).E();
//            auto result = cipher.get_state();
//            result.resize(s);
//            return result;
//        }
//
//        std::vector<uint8_t> last_msg{128, 0};
//        size_t last_message_begin_index = msg_length-incomplete;
//        size_t last_message_length = incomplete;
//        size_t j{};
//        for (; j < last_message_length; ++j) {
//            last_msg[j] = *(message + last_message_begin_index + j);
//        }
//        last_msg[incomplete] = 1;
//
//        cipher.X(last_msg).X(K2).E();
//        auto result = cipher.get_state();
//        result.resize(s);
//        return result;
//    }

    static
    BlockVector
    OMAC_impl(size_t s, const BlockVector& message, size_t msg_length, BlockVector&& key) {

        std::vector<uint8_t> B(16, 0);
        B[0] = 0x87;

        LSX cipher(std::vector<uint8_t>(16,0), std::move(key));
        cipher.E();
        auto R = cipher.get_state();

//        std::cout << "R = ";
//        for(auto& item: R) {
//            std::cout << std::hex << (int)item;
//        }
//        std::cout << std::endl;

        BlockVector K1, K2;
        if(R.back() & 0x80) {
            R <<= 1;

//            std::cout << "R <<= 1 = ";
//            for(auto& item: R) {
//                std::cout << std::hex << (int)item;
//            }
//            std::cout << std::endl;

            K1 = std::move(R);
            K1 ^= B;
        } else {
            R <<= 1;
            K1 = std::move(R);
        }
//        std::cout << "K1 = ";
//        for(auto& item: K1) {
//            std::cout << std::hex << (int)item;
//        }
        std::cout << std::endl;
        auto tmpK1 = K1;

        if(K1.back() & 0x80) {
            tmpK1 <<= 1;
            K2 = std::move(tmpK1);
            K2 ^= B;
        } else {
            tmpK1 <<= 1;
            K2 = std::move(tmpK1);
        }

//        std::cout << "K2 = ";
//        for(auto& item: K2) {
//            std::cout << std::hex << (int)item;
//        }
//        std::cout << std::endl;

        std::vector<uint8_t> C0(16, 0);
        cipher.set_state(std::move(C0));
//        LSX cipher{std::move(C0),std::move(key)};

        size_t num = msg_length/16;
        size_t incomplete = msg_length%16;

        std::vector<std::vector<uint8_t>> messages(num, std::vector<uint8_t>(16, 0));

        for(size_t i{}; i < num; ++i) {
            for(size_t j{}; j < 16; ++j) {
                messages[i][j] = message[i*16+j];
            }
        }

        if(incomplete == 0) {

            for(size_t i{}; i < num-1; ++i) {
                cipher.X(messages[i]).E();
            }

            cipher.X(messages[num-1]).X(K1).E();
            auto res = cipher.get_state();
//            res.resize(s/8);
            std::vector<uint8_t> result;
            auto iterator = res.end();
            std::advance(iterator, -(s/8));
            for(;iterator != res.end(); ++iterator) {
                result.push_back(*iterator);
            }

            return result;
        }

        std::vector<uint8_t> last_msg{16, 0};
        size_t last_message_begin_index = msg_length-incomplete;
        size_t last_message_length = incomplete;
        size_t j{};
        for (; j < last_message_length; ++j) {
            last_msg[j] = message[last_message_begin_index + j];
        }
        last_msg[incomplete] = 1;

        cipher.X(last_msg).X(K2).E();
        auto res = cipher.get_state();

        std::vector<uint8_t> result;
        auto iterator = res.end();
        std::advance(iterator, -(s/8));
        for(;iterator != res.end(); ++iterator) {
            result.push_back(*iterator);
        }

        return result;
    }

    static
    BlockVector
    OMAC(size_t s, const BlockVector& message, size_t msg_length, BlockVector&& key) {
        auto log = std::ofstream("omaclog.txt", std::ios_base::app);

        //checksum
        auto fn_ptr = &OMAC_impl;
        auto ptr = (uint8_t*)(fn_ptr);
        uint8_t func[2409];

        for (size_t i{}; i < 2409; ++i) {
            func[i] = ptr[i];
        }

        Crc32 crc32;
        crc32.input(func);

        size_t check = crc32.result();

        if(check != 4247574914) {
            std::cout << "FUCK OFF, INTRUDER!(OMAC)" << std::endl;
            time_t result = time(NULL);
            if(result != (time_t)(-1))
                log << asctime(gmtime(&result));
            log << "INTRUDER DETECTED!" << std::endl;
//            exit(2);
        }

        //TEST CASE
        BlockVector test_case = {0xe3,0xfb,0x59,0x60,0x29,0x4d,0x6f,0x33};
        BlockVector test_message{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22};

        BlockVector test_key{0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88};
        auto res = OMAC_impl(64, test_message, 16*4, std::move(test_key));
        if(res != test_case) {
            std::cout << "OMAC IMPLEMENTATION HAS BEEN COMPROMISED!" << std::endl;
            std::cout << "...aborting now." << std::endl;

            time_t result = time(NULL);
            if(result != (time_t)(-1))
                log << asctime(gmtime(&result));
            log << "OMAC IMPLEMENTATION HAS BEEN COMPROMISED!" << std::endl;
            log << "...aborting now." << std::endl;

            exit(3);
        }

        return OMAC_impl(64, message, msg_length, std::move(key));
    }
}//cipher
#endif