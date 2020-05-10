## Build
```
$ protoc -I=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` --grpc_out=. Messages.proto
$ protoc -I=.  --cpp_out=.  Messages.proto
```


docker内でビルドしたい場合，イメージ内に`grpc_cpp_plugin`が入っていないのでなんとかしていれる必要がある

例えば
```
$ git clone -b ${GRPC_RELEASE_TAG} https://github.com/grpc/grpc /var/local/git/grpc
$ cd /var/local/git/grpc
$ git submodule update --init --recursive
$ make -j$(nproc) && make install && make clean && ldconfig
```
