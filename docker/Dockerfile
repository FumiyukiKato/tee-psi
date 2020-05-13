# 本番ではスリムにしてマルチステージビルドするのがよさそう
FROM baiduxlab/sgx-rust

RUN sudo apt-get update && sudo apt-get install unzip

ENV GRPC_RELEASE_TAG v1.28.0
RUN git clone -b ${GRPC_RELEASE_TAG} https://github.com/grpc/grpc /var/local/git/grpc && \
    cd /var/local/git/grpc && \
    git submodule update --init --recursive 

RUN mkdir -p cmake/build && cd cmake/build && cmake ../.. -DgRPC_INSTALL=ON \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_INSTALL_PREFIX=/usr/local

RUN make && make install

RUN cd ../.. && make install && make clean && ldconfig
