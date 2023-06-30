//
// Created by kadius on 19.05.23.
//

#ifndef TESTPROJECT_HMAC_HPP
#define TESTPROJECT_HMAC_HPP


#include "Streebog.hpp"


using namespace hash;

struct HMAC {

    HMAC() {
    }

    template<size_t N, size_t M>
    void operator()(const uint8_t (&key)[N],  const uint8_t (&msg)[M], uint8_t (&dest)[512]) {
        hash.reset();
        auto buf1 = new uint8_t[N+M];

        size_t i{};
        for(; i < N; ++i) {
            *(buf1+i) = key[i]^0x36;
        }

        for(; i < N+M; ++i) {
            *(buf1+i) = msg[i-N];
        }

        auto buf2 = new uint8_t[64+N];

        hash(buf1, N+M, buf2+N);

        i = 0;
        for(; i < N; ++i) {
            *(buf2+i) = key[i]^0x5c;
        }

        hash.reset();
        hash(buf2, 64+N, dest);
    }


    template<size_t N>
    void operator()(const uint8_t (&key)[N],  const std::vector<uint8_t>& msg, uint8_t (&dest)[512]) {
        auto M = msg.size();
        hash.reset();
        auto buf1 = new uint8_t[N+M];

        size_t i{};
        for(; i < N; ++i) {
            *(buf1+i) = key[i]^0x36;
        }

        for(; i < N+M; ++i) {
            *(buf1+i) = msg[i-N];
        }

        auto buf2 = new uint8_t[64+N];

        hash(buf1, N+M, buf2+N);

        i = 0;
        for(; i < N; ++i) {
            *(buf2+i) = key[i]^0x5c;
        }

        hash.reset();
        hash(buf2, 64+N, dest);
    }

private:
    Streebog hash{512};
};



template<size_t N, size_t Tl>
static
void
kdf1(const uint8_t (&T)[Tl], const uint8_t (&S)[N], uint8_t (&D)[512]) {
    HMAC hmac;
    hmac(T, S, D);
}

template<size_t N, size_t M, size_t Tl, size_t L>
static
void
kdf2(const uint8_t (&S)[N], const uint8_t (&T)[Tl], const uint8_t (&Zi_1)[M], size_t C, const std::string& P, const std::string& U,/* const size_t A, const size_t L*/ uint8_t (&dest)[L]){

    uint8_t D[512] = {};
    kdf1(T, S, D);

//    std::cout << "WTF";
    size_t P_size = P.size();
    std::cout << P << std::endl;
    std::cout << U << std::endl;
    size_t U_size = U.size();
    std::vector<uint8_t> formatted(M+P.size()+U.size()+4, 0);

    size_t i{};
    for(; i < M; ++i) {
        formatted[i] = Zi_1[i];
    }
    for(; i < M+P_size; ++i) {
        formatted[i] = P[i];
    }
    for(; i < M+P_size+U_size; ++i) {
        formatted[i] = U[i];
    }

    for(size_t j{}; j < 4; ++j) {
        auto c = C;
        uint8_t val = c;

        formatted[M+P_size+U_size+j] = val;

        c >>= 8;
    }


    uint8_t K1[256] = {};
    for(size_t j{}; j < 256; ++j) {
        K1[j] = D[j];
    }

    HMAC hmac;
    hmac(K1, formatted, D);

    for(size_t j{}; j < L; ++j) {
        dest[j] = D[j];
    }
}












#endif //TESTPROJECT_HMAC_HPP
