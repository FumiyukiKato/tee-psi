# 本番ではスリムにしてマルチステージビルドするのがよさそう
FROM baiduxlab/sgx-rust

ENV GRPC_RELEASE_TAG v1.28.1
RUN git clone -b ${GRPC_RELEASE_TAG} https://github.com/grpc/grpc /var/local/git/grpc && \
    cd /var/local/git/grpc && \
    git submodule update --init --recursive

RUN echo "-- installing grpc" && \
    cd /var/local/git/grpc && \
    make -j$(nproc) && make install && make clean && ldconfig
