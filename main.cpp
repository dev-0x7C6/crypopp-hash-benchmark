#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <benchmark/benchmark.h>
#include <cryptopp/cryptlib.h>

#include <cryptopp/sha.h>
#include <cryptopp/md2.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/whrlpool.h>

static std::vector<char> dataset;

using namespace CryptoPP;

template <typename hash_type>
void hash_benchmark(benchmark::State &state) {
    while (state.KeepRunning()) {
        hash_type hash;
        std::vector<char> digest;
        digest.resize(hash.DigestSize());
        hash.Update(reinterpret_cast<const byte*>(dataset.data()), dataset.size());
        hash.Final(reinterpret_cast<byte*>(&digest[0]));
    }
}

BENCHMARK(hash_benchmark<Whirlpool>);
BENCHMARK(hash_benchmark<SHA1>);
BENCHMARK(hash_benchmark<SHA224>);
BENCHMARK(hash_benchmark<SHA256>);
BENCHMARK(hash_benchmark<SHA384>);
BENCHMARK(hash_benchmark<SHA512>);
BENCHMARK(hash_benchmark<Weak::MD2>);
BENCHMARK(hash_benchmark<Weak::MD4>);
BENCHMARK(hash_benchmark<Weak::MD5>);

auto main(int argc, char **argv) -> int {
    dataset.resize(1024 * 1024); // 1 MiB dataset
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
    return 0;
}
