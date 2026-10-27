# Build local shared crates from the monorepo root:
# docker build -f idfrog/Dockerfile -t idfrog .
# Add --build-arg FEATURES=dynamodb for DynamoDB grant state.
FROM rust:slim-trixie AS planner
COPY --from=nresare/cargo-chef:binonly /cargo-chef /bin/cargo-chef
WORKDIR /build
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:slim-trixie AS builder
ARG FEATURES=""
WORKDIR /build
COPY --from=planner /bin/cargo-chef /bin/cargo-chef
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --locked --release --package idfrog --features "$FEATURES" --recipe-path recipe.json
COPY . .
RUN cargo build --locked --release -p idfrog --features "$FEATURES"

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=builder /build/target/release/idfrog /idfrog
ENTRYPOINT ["/idfrog"]
