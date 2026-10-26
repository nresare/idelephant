# Build local shared crates from the monorepo root:
# docker build -f idfrog/Dockerfile -t idfrog .
FROM rust:slim-trixie AS planner
COPY --from=nresare/cargo-chef:binonly /cargo-chef /bin/cargo-chef
WORKDIR /build
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:slim-trixie AS builder
WORKDIR /build
COPY --from=planner /bin/cargo-chef /bin/cargo-chef
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --locked --release --package idfrog --recipe-path recipe.json
COPY . .
RUN cargo build --locked --release -p idfrog

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=builder /build/target/release/idfrog /idfrog
ENTRYPOINT ["/idfrog"]
