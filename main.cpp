#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <benchmark/benchmark.h>
#include <cryptopp/cryptlib.h>

#include <cryptopp/sha.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/whrlpool.h>

#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/whrlpool.h>

constexpr auto KiB = 1024;
constexpr auto MiB = KiB * 1024;
constexpr auto DATASET_SIZE = MiB * 256; // 256 MiB
constexpr auto DATASET_CHUNK = MiB; // process 1MiB at time

const static auto DATASET = // 256 MiB of vector data, filled with 0,1,2,...,255,0,1,...
    []() {
        std::vector<unsigned char> dataset;
        auto counter = 0;
        for (auto &data : dataset)
            data = counter++;
        dataset.resize(DATASET_SIZE);
        return dataset;
    }(); // inplace lambda

enum class Hash {
    Whirlpool,
    MD4,
    MD5,
    SHA1,
    SHA256,
    SHA384,
    SHA512,
};

template <typename hash_type>
std::vector<unsigned char> cryptopp_hash(const unsigned char *data, const std::size_t size) {
    using namespace CryptoPP;
    hash_type hash;
    auto digest = [&]() {
        std::vector<unsigned char> ret;
        ret.resize(hash.DigestSize());
        return ret;
    }();

    hash.Update(reinterpret_cast<const byte *>(data), size);
    hash.Final(reinterpret_cast<byte *>(&digest[0]));

    return digest;
}

template <Hash type>
std::vector<unsigned char> cryptopp_algo_wrapper(const unsigned char *data, const std::size_t size) {
    switch (type) {
        case Hash::Whirlpool: return cryptopp_hash<CryptoPP::Whirlpool>(data, size);
        case Hash::MD4: return cryptopp_hash<CryptoPP::Weak::MD4>(data, size);
        case Hash::MD5: return cryptopp_hash<CryptoPP::Weak::MD5>(data, size);
        case Hash::SHA1: return cryptopp_hash<CryptoPP::SHA1>(data, size);
        case Hash::SHA256: return cryptopp_hash<CryptoPP::SHA256>(data, size);
        case Hash::SHA384: return cryptopp_hash<CryptoPP::SHA384>(data, size);
        case Hash::SHA512: return cryptopp_hash<CryptoPP::SHA512>(data, size);
    }
}

template <Hash>
std::vector<unsigned char> openssl_algo_wrapper(const unsigned char *data, const std::size_t size) {
    std::terminate();
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::MD5>(const unsigned char *data, const std::size_t size) {
    std::vector<unsigned char> digest;
    digest.resize(MD5_DIGEST_LENGTH);
    MD5(data, size, digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::MD4>(const unsigned char *data, const std::size_t size) {
    std::vector<unsigned char> digest;
    digest.resize(MD4_DIGEST_LENGTH);
    MD4(data, size, digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::Whirlpool>(const unsigned char *data, const std::size_t size) {
    std::vector<unsigned char> digest;
    digest.resize(WHIRLPOOL_DIGEST_LENGTH);
    WHIRLPOOL(data, size, digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::SHA1>(const unsigned char *data, const std::size_t size) {
    std::vector<unsigned char> digest;
    digest.resize(SHA_DIGEST_LENGTH);
    SHA1(data, size, digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::SHA256>(const unsigned char *data, const std::size_t size) {
    std::vector<unsigned char> digest;
    digest.resize(SHA256_DIGEST_LENGTH);
    SHA256(data, size, digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::SHA384>(const unsigned char *data, const std::size_t size) {
    std::vector<unsigned char> digest;
    digest.resize(SHA384_DIGEST_LENGTH);
    SHA384(data, size, digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::SHA512>(const unsigned char *data, const std::size_t size) {
    std::vector<unsigned char> digest;
    digest.resize(SHA512_DIGEST_LENGTH);
    SHA512(data, size, digest.data());
    return digest;
}

template <Hash algo>
void cryptopp(benchmark::State &state) {
    while (state.KeepRunning()) {
        const auto offset = DATASET.data() + (state.bytes_processed() % DATASET_SIZE);
        const auto ret = cryptopp_algo_wrapper<algo>(offset, DATASET_CHUNK);
        static_cast<void>(ret);
        state.SetBytesProcessed(state.bytes_processed() + DATASET_CHUNK);
    }
}

template <Hash algo>
void openssl(benchmark::State &state) {
    while (state.KeepRunning()) {
        const auto offset = DATASET.data() + (state.bytes_processed() % DATASET_SIZE);
        const auto ret = openssl_algo_wrapper<algo>(offset, DATASET_CHUNK);
        static_cast<void>(ret);
        state.SetBytesProcessed(state.bytes_processed() + DATASET_CHUNK);
    }
}

BENCHMARK(cryptopp<Hash::MD4>);
BENCHMARK(cryptopp<Hash::MD5>);
BENCHMARK(cryptopp<Hash::SHA1>);
BENCHMARK(cryptopp<Hash::SHA256>);
BENCHMARK(cryptopp<Hash::SHA384>);
BENCHMARK(cryptopp<Hash::SHA512>);
BENCHMARK(cryptopp<Hash::Whirlpool>);
BENCHMARK(openssl<Hash::MD4>);
BENCHMARK(openssl<Hash::MD5>);
BENCHMARK(openssl<Hash::SHA1>);
BENCHMARK(openssl<Hash::SHA256>);
BENCHMARK(openssl<Hash::SHA384>);
BENCHMARK(openssl<Hash::SHA512>);
BENCHMARK(openssl<Hash::Whirlpool>);

auto main(int argc, char **argv) -> int {
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::AddCustomContext("Memory table", std::to_string(DATASET_SIZE / MiB) + " MiB");
    ::benchmark::AddCustomContext("Memory chunk", std::to_string(DATASET_CHUNK / MiB) + " MiB");
    ::benchmark::RunSpecifiedBenchmarks();
    return 0;
}
