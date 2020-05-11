## Build
```
$ protoc -I=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` --grpc_out=. Messages.proto
$ protoc -I=.  --cpp_out=.  Messages.proto
```
