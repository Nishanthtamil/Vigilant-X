# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: LLVM Toolchain + MSan-instrumented libc++
# ─────────────────────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS toolchain

ENV DEBIAN_FRONTEND=noninteractive

# Install LLVM and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang-17 \
    clang++-17 \
    llvm-17 \
    llvm-17-dev \
    libclang-rt-17-dev \
    lld-17 \
    lldb-17 \
    libclang-17-dev \
    libfuzzer-17-dev \
    libgtest-dev \
    cmake \
    ninja-build \
    make \
    git \
    curl \
    ca-certificates \
    openjdk-17-jre-headless \
    python3 \
    unzip \
    wget \
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-17 100 \
    && update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-17 100 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1a: Install Joern
# ─────────────────────────────────────────────────────────────────────────────
RUN wget https://github.com/joernio/joern/releases/latest/download/joern-cli.zip -O /tmp/joern-cli.zip && \
    unzip /tmp/joern-cli.zip -d /opt && \
    mv /opt/joern-cli /opt/joern && \
    rm /tmp/joern-cli.zip && \
    ln -s /opt/joern/joern /usr/local/bin/joern && \
    ln -s /opt/joern/joern-parse /usr/local/bin/joern-parse && \
    ln -s /opt/joern/joern-export /usr/local/bin/joern-export

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1b: Build instrumented libc++ for MSan
# ─────────────────────────────────────────────────────────────────────────────
# MSan requires ALL libraries to be instrumented. We build libc++ as it's the 
# most common dependency for C++ PoCs.
RUN git clone --depth 1 -b llvmorg-17.0.6 https://github.com/llvm/llvm-project.git /llvm-project

RUN mkdir -p /llvm-project/build-msan && cd /llvm-project/build-msan && \
    cmake ../runtimes \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DLLVM_USE_SANITIZER=MemoryWithOrigins \
    && ninja cxx cxxabi

# Build GoogleTest as a static lib (standard build for ASan/UBSan)
RUN cd /usr/src/googletest && \
    cmake . -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc) && make install

# Build instrumented GoogleTest for MSan
RUN mkdir -p /usr/src/googletest/build-msan && cd /usr/src/googletest/build-msan && \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_CXX_FLAGS="-fsanitize=memory -fsanitize-memory-track-origins -stdlib=libc++ -I/llvm-project/build-msan/include -I/llvm-project/build-msan/include/c++/v1" \
        -DCMAKE_EXE_LINKER_FLAGS="-L/llvm-project/build-msan/lib -lc++ -lc++abi -Wl,-rpath,/llvm-project/build-msan/lib" \
    && make -j$(nproc)

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Python orchestrator
# ─────────────────────────────────────────────────────────────────────────────
FROM toolchain AS orchestrator

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 python3.12-dev python3.12-venv patch \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml .
RUN python3.12 -m pip install --no-cache-dir --break-system-packages -e ".[dev]"

COPY vigilant/ vigilant/
COPY code_law/ code_law/
COPY examples/ examples/

# ─────────────────────────────────────────────────────────────────────────────
# Stage 3: Sandbox-only image
# ─────────────────────────────────────────────────────────────────────────────
FROM toolchain AS sandbox
LABEL vigilant.role="sandbox"
WORKDIR /workspace
RUN mkdir -p /workspace/build

# Copy the MSan-instrumented libraries to a known location in the final image
RUN mkdir -p /msan-libs && \
    cp -r /llvm-project/build-msan/lib /msan-libs/lib && \
    cp -r /llvm-project/build-msan/include /msan-libs/include && \
    cp /usr/src/googletest/build-msan/lib/*.a /msan-libs/lib/
