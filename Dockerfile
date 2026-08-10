FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p weftd

FROM debian:stable-slim
COPY --from=build /src/target/release/weftd /usr/local/bin/weftd
EXPOSE 8747
USER 1000
CMD ["weftd", "8747", "--demo", "--readonly"]
