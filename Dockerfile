# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: LLVM Toolchain + GoogleTest + LibFuzzer
# ─────────────────────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS toolchain

ENV DEBIAN_FRONTEND=noninteractive

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
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-17 100 \
    && update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-17 100 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Build GoogleTest as a static lib
RUN cd /usr/src/googletest && \
    cmake . -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc) && make install

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
# Stage 3: Sandbox-only image (used by sandbox_runner.py internally)
# Lightweight: just the compiler + sanitizers. No Python.
# ─────────────────────────────────────────────────────────────────────────────
FROM toolchain AS sandbox
LABEL vigilant.role="sandbox"
WORKDIR /workspace
# Repo source is mounted at /repo (read-only) at runtime
# Build artifacts go to /workspace/build (writable)
RUN mkdir -p /workspace/build

