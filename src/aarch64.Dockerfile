FROM balenalib/aarch64-ubuntu:latest

ARG BPFTOOL_TAG=main
ARG BPFTOOL_SRC=https://github.com/libbpf/bpftool.git

RUN apt update
RUN apt install --quiet --yes \
    build-essential \
    gcc \
    make \
    clang \
    llvm \
    git \
    libelf-dev \
    binutils-dev \
    libbpf-dev \
    libcap-dev \
    wget

RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git
WORKDIR bpftool/src
RUN make
RUN make install

ADD ./src /tmp/src/
WORKDIR /tmp/src
RUN make static