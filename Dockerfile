# 构建阶段:release 构建会把 frontend/ 编译进二进制(rust-embed),运行时无需前端文件
FROM rust:bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release

# 运行阶段:精简镜像
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/research-tool-key-pool /app/research-tool-key-pool
EXPOSE 8787
# SQLite 数据库落此目录,挂载持久化
VOLUME ["/app/data"]
CMD ["./research-tool-key-pool"]
