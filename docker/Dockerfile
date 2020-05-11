# 本番ではスリムにしてマルチステージビルドするのがよさそう
FROM baiduxlab/sgx-rust

ENV GRPC_RELEASE_TAG v1.28.1
RUN git clone -b ${GRPC_RELEASE_TAG} https://github.com/grpc/grpc /var/local/git/grpc && \
    cd /var/local/git/grpc && \
    git submodule update --init --recursive

RUN echo "-- installing grpc" && \
    cd /var/local/git/grpc && \
    make -j$(nproc) && make install && make clean && ldconfig

RUN cd /root && wget -O /root/v3.11.4.tar.gz https://github.com/google/protobuf/archive/v3.11.4.tar.gz && \
    tar xzf v3.11.4.tar.gz && \
    cd /root/protobuf-3.11.4 && \
    ./autogen.sh && ./configure && make -j && make -j install && ldconfig && cd .. && rm -rf protobuf-3.11.4 v3.11.4.tar.gz
