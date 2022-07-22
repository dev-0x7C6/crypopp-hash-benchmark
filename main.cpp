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

const static auto dataset = []() {
    constexpr auto size = 1024 * 1024; // 1 MiB dataset
    std::vector<unsigned char> dataset;
    dataset.resize(size);
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
std::vector<unsigned char> cryptopp_hash(const std::vector<unsigned char> &data) {
    using namespace CryptoPP;
    hash_type hash;
    std::vector<unsigned char> digest;
    digest.resize(hash.DigestSize());
    hash.Update(reinterpret_cast<const byte *>(data.data()), data.size());
    hash.Final(reinterpret_cast<byte *>(&digest[0]));
    return digest;
}

template <Hash type>
std::vector<unsigned char> cryptopp_algo_wrapper(const std::vector<unsigned char> &data) {
    switch (type) {
        case Hash::Whirlpool: return cryptopp_hash<CryptoPP::Whirlpool>(data);
        case Hash::MD4: return cryptopp_hash<CryptoPP::Weak::MD4>(data);
        case Hash::MD5: return cryptopp_hash<CryptoPP::Weak::MD5>(data);
        case Hash::SHA1: return cryptopp_hash<CryptoPP::SHA1>(data);
        case Hash::SHA256: return cryptopp_hash<CryptoPP::SHA256>(data);
        case Hash::SHA384: return cryptopp_hash<CryptoPP::SHA384>(data);
        case Hash::SHA512: return cryptopp_hash<CryptoPP::SHA512>(data);
    }
}

template <Hash algo>
void cryptopp(benchmark::State &state) {
    while (state.KeepRunning()) {
        const auto ret = cryptopp_algo_wrapper<algo>(dataset);
        static_cast<void>(ret);
    }
}

template <Hash>
std::vector<unsigned char> openssl_algo_wrapper(const std::vector<unsigned char> &data) {
    std::terminate();
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::MD5>(const std::vector<unsigned char> &data) {
    std::vector<unsigned char> digest;
    digest.resize(MD5_DIGEST_LENGTH);
    MD5(dataset.data(), dataset.size(), digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::MD4>(const std::vector<unsigned char> &data) {
    std::vector<unsigned char> digest;
    digest.resize(MD4_DIGEST_LENGTH);
    MD4(dataset.data(), dataset.size(), digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::Whirlpool>(const std::vector<unsigned char> &data) {
    std::vector<unsigned char> digest;
    digest.resize(WHIRLPOOL_DIGEST_LENGTH);
    WHIRLPOOL(dataset.data(), dataset.size(), digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::SHA1>(const std::vector<unsigned char> &data) {
    std::vector<unsigned char> digest;
    digest.resize(SHA_DIGEST_LENGTH);
    SHA1(dataset.data(), dataset.size(), digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::SHA256>(const std::vector<unsigned char> &data) {
    std::vector<unsigned char> digest;
    digest.resize(SHA256_DIGEST_LENGTH);
    SHA256(dataset.data(), dataset.size(), digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::SHA384>(const std::vector<unsigned char> &data) {
    std::vector<unsigned char> digest;
    digest.resize(SHA384_DIGEST_LENGTH);
    SHA384(dataset.data(), dataset.size(), digest.data());
    return digest;
}

template <>
std::vector<unsigned char> openssl_algo_wrapper<Hash::SHA512>(const std::vector<unsigned char> &data) {
    std::vector<unsigned char> digest;
    digest.resize(SHA512_DIGEST_LENGTH);
    SHA512(dataset.data(), dataset.size(), digest.data());
    return digest;
}

template <Hash algo>
void openssl(benchmark::State &state) {
    while (state.KeepRunning()) {
        const auto ret = openssl_algo_wrapper<algo>(dataset);
        static_cast<void>(ret);
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
    ::benchmark::AddCustomContext("Memory chunk", std::to_string(dataset.size()) + " bytes");
    ::benchmark::RunSpecifiedBenchmarks();
    return 0;
}
