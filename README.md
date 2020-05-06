# tee-psi

- original repository
  - https://github.com/apache/incubator-teaclave-sgx-sdk/tree/31b323366cbab3b359fd4a3a9bc827ff37654059/samplecode/psi
  - dependencies are [here](https://github.com/apache/incubator-teaclave-sgx-sdk/blob/e60e5adfadcbe4b34913d1c82cd5f7ac021fc3cf/samplecode/psi/README.md#setup)

- material
  - https://medium.com/baiduxlab/private-set-intersection-technology-a-hot-topic-in-multi-party-computing-f560cf3bf6cb
  - high level architecture and phirosophy of PSI on P2P

### Setup
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
