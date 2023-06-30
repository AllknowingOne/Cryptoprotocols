//
// Created by kadius on 04.04.23.
//

#include "LSX.hpp"

namespace cipher {
LSX& X_impl(LSX& cipher, const BlockVector& key) {
    for(size_t i = 0; i < cipher.state_size_; ++i) {
        cipher.state_[i] ^= key[i];
    }

    return cipher;
}

LSX& LSX::X(const BlockVector& key) {
    return X_impl(*this, key);
}

void X_impl_2(LSX& cipher, BlockVector& state, const BlockVector& key) {
    for(size_t i{}; i < cipher.state_size_; ++i) {
        state[i] ^= key[i];
    }
}

void LSX::X(BlockVector& state, const BlockVector& key) {
    X_impl_2(*this, state, key);
}

LSX& S_impl_1(LSX& cipher) {
    for (size_t i{}; i < cipher.state_size_; ++i) {
        cipher.state_[i] = cipher.sbox_[cipher.state_[i]];
    }

    return cipher;
}


LSX& LSX::S() {
    return S_impl_1(*this);
}


void S_impl_2(LSX& cipher, BlockVector& state) {
    for (size_t i{}; i < cipher.state_size_; ++i) {
        state[i] = cipher.sbox_[state[i]];
    }
}

void LSX::S(BlockVector& state) {
    S_impl_2(*this, state);
}

LSX& R_impl_1(LSX& cipher) {

    uint8_t l{cipher.state_[0]};

    for(size_t i{1}; i < cipher.state_size_; ++i) {
        l ^= gf_mult(cipher.lvec_[i], cipher.state_[i]);
        cipher.state_[i-1] = cipher.state_[i];
    }

    cipher.state_[15] = l;

    return cipher;
}

LSX& LSX::R() {
    return R_impl_1(*this);
}

LSX& R_impl_2(LSX& cipher, BlockVector& state) {

    uint8_t l{state[0]};

    for(size_t i{1}; i < cipher.state_size_; ++i) {
        l ^= gf_mult(cipher.lvec_[i], state[i]);
        state[i-1] = state[i];
    }

    state[15] = l;

    return cipher;
}

LSX& LSX::R(BlockVector& state) {
    return R_impl_2(*this, state);
}

LSX& LSX::L() {

    for(size_t i{}; i < state_size_; ++i) {
        R();
    }

    return *this;
}

LSX& LSX::L(BlockVector& state) {

    for(size_t i{}; i < state_size_; ++i) {
        R(state);
    }

    return *this;
}

//Feistel function
auto
LSX::F(const BlockVector& Ki, const BlockVector& C)
-> BlockVector
{

    auto internal = Ki;

    X(internal, C);
    S(internal);
    L(internal);

    return internal;
}

//Feistel net
auto
LSX::key_schedule()//16-byte master key
-> void
{
    BlockVector K1;
    BlockVector K2;

    size_t i{};
    for(; i < 16; ++i)
        K2.push_back(master_key_[i]);

    for(; i < 32; ++i)
        K1.push_back(master_key_[i]);

    keys_.emplace_back(std::move(K1));
    keys_.emplace_back(std::move(K2));

    auto r = keys_[0];
    auto l = keys_[1];
    for(i = 0; i < 4; ++i) {
        for (size_t j{}; j < 8; ++j) {
            auto old_r = r;
            auto internal = F(r, round_constants_[8*i+j]);
            r = l ^ internal;
            l = old_r;
        }
        keys_.emplace_back(r);
        keys_.emplace_back(l);
    }
}

void
LSX::E() {
    for(size_t round{}; round < 9; ++round)
        X(keys_[round]).S().L();

    X(keys_[9]);
}

void
LSX::E(BlockVector&& msg) {
    state_ = std::move(msg);

    for(size_t round{}; round < 9; ++round)
        X(keys_[round]).S().L();

    X(keys_[9]);
}

}