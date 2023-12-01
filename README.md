## Preview

Cpu sample: AMD Ryzen 9 3900X 12-Core Processor

Memory: 64GiB @ 3200Mhz

```
Running ./cryptographic-hash-benchmark
Run on (24 X 3727.43 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x12)
  L1 Instruction 32 KiB (x12)
  L2 Unified 512 KiB (x12)
  L3 Unified 16384 KiB (x4)
Load Average: 0.92, 8.08, 9.31
Memory chunk: 1 MiB
Memory table: 256 MiB
------------------------------------------------------------------------------------
Benchmark                          Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------
zlib_adler                    265115 ns       264393 ns         2560 bytes_per_second=3.6936Gi/s
zlib_crc32                    323533 ns       322383 ns         2186 bytes_per_second=3.0292Gi/s
cryptopp<Hash::Adler>         343543 ns       343021 ns         2054 bytes_per_second=2.84695Gi/s
cryptopp<Hash::CRC32>        1703755 ns      1701936 ns          405 bytes_per_second=587.566Mi/s
cryptopp<Hash::MD4>           985631 ns       984404 ns          717 bytes_per_second=1015.84Mi/s
cryptopp<Hash::MD5>          1698783 ns      1696744 ns          410 bytes_per_second=589.364Mi/s
cryptopp<Hash::SHA1>          538079 ns       537441 ns         1308 bytes_per_second=1.81706Gi/s
cryptopp<Hash::SHA256>        490450 ns       489862 ns         1430 bytes_per_second=1.99355Gi/s
cryptopp<Hash::SHA384>       1693047 ns      1691192 ns          416 bytes_per_second=591.299Mi/s
cryptopp<Hash::SHA512>       1681841 ns      1680022 ns          419 bytes_per_second=595.23Mi/s
cryptopp<Hash::Whirlpool>    4156297 ns      4151707 ns          170 bytes_per_second=240.865Mi/s
openssl<Hash::Adler>      ERROR OCCURRED: 'skip, no implementation'
openssl<Hash::CRC32>      ERROR OCCURRED: 'skip, no implementation'
openssl<Hash::MD4>            930935 ns       929936 ns          748 bytes_per_second=1.05014Gi/s
openssl<Hash::MD5>           1217045 ns      1215645 ns          577 bytes_per_second=822.608Mi/s
openssl<Hash::SHA1>           461023 ns       460484 ns         1506 bytes_per_second=2.12073Gi/s
openssl<Hash::SHA256>         494146 ns       493611 ns         1401 bytes_per_second=1.97841Gi/s
openssl<Hash::SHA384>        1145275 ns      1144022 ns          612 bytes_per_second=874.109Mi/s
openssl<Hash::SHA512>        1144665 ns      1143455 ns          612 bytes_per_second=874.542Mi/s
openssl<Hash::Whirlpool>     4641008 ns      4636575 ns          151 bytes_per_second=215.676Mi/s

Process exited with code: 0
```
