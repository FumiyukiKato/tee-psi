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

protocだけ
https://gist.github.com/ryujaehun/991f5f1e8c1485dea72646877707f497

C++ライブラリ
https://askubuntu.com/questions/1072683/how-can-i-install-protoc-on-ubuntu-16-04
