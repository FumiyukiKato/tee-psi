# tee-psi

- original
  - https://github.com/apache/incubator-teaclave-sgx-sdk/tree/31b323366cbab3b359fd4a3a9bc827ff37654059/samplecode/psi
  - dependencies are here

- material
  - https://medium.com/baiduxlab/private-set-intersection-technology-a-hot-topic-in-multi-party-computing-f560cf3bf6cb
  - high level architecture and phirosophy of PSI on P2P

#### Enviroment variables 
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

#### Run server and other nesessary SGX service
```
$ bin/up
```

#### Run client
