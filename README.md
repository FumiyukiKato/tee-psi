# tee-psi

TEE-based Private Set Intersection

![TEE-PSI 001](https://user-images.githubusercontent.com/27177602/81140452-57e11a00-8fa4-11ea-870e-c1b1d4e932f5.jpeg)


### Materials

#### original repository
  - https://github.com/apache/incubator-teaclave-sgx-sdk/tree/31b323366cbab3b359fd4a3a9bc827ff37654059/samplecode/psi
  - dependencies are [here](https://github.com/apache/incubator-teaclave-sgx-sdk/blob/e60e5adfadcbe4b34913d1c82cd5f7ac021fc3cf/samplecode/psi/README.md#setup)

#### high level architecture
  - https://medium.com/baiduxlab/private-set-intersection-technology-a-hot-topic-in-multi-party-computing-f560cf3bf6cb

### Setup

Clone rust sgx sdk and set environment variables
```
$ git clone git@github.com:apache/incubator-teaclave-sgx-sdk.git
```

#### Enviroment variables hints
`.env`
```
# Rust SGX SDK from baidu, clone from here https://github.com/apache/incubator-teaclave-sgx-sdk/tree/31b323366cbab3b359fd4a3a9bc827ff37654059
RUST_SDK_ROOT=/path/to/rust-sgx-sdk
TEE_PSI=/path/to/this_dir

# Client-Server TLS certification, make by yourself
SERVER_KEY_PATH=
SERVER_CRT_PATH=

# IAS authentication dredential (see https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf)
AS_PRIMARY_KEY=
RA_SPID=
```
### Build
using Docker

```
$ bin/up
```

#### Server
```
$ bin/in
$ cd SMCServer
$ make SGX_MODE=HW SGX_PRERELEASE=1
```

#### Client
```
$ bin/in
$ cd SMCClient
$ make
```

### Run

#### SGX ASEM service
```
$ bin/up
```

##### Run Server
```
$ bin/in
$ cd SMCServer
$ ./app [-f central data file path]
```

##### Run client
```
$ bin/in
$ cd SMCClient
$ ./app [-f file path] [-m mode]
```

### Other

#### geohash data generator
```
$ python script/geohash_data_generator.py [ --num data_size ] [ --mode (random|order) ]
```

### https curl

```
$ curl --cacert path/to/server.crt https://localhost:50001
```
