# SPDX-License-Identifier: MIT
# Copyright (c) 2026 idelephant contributors

FROM rust:1.93-trixie AS builder

WORKDIR /build

COPY . ./

RUN cargo build --release -p idelephant

FROM gcr.io/distroless/cc-debian13:nonroot

COPY --from=builder /build/target/release/idelephant /

CMD ["/idelephant"]
