# Lemon Wire index server.
#   docker build -t lemonwire-server .
#   docker run --rm -v lemonwire-data:/data lemonwire-server init --index-name ... --admin-pubkey ...
#   docker run -d -v lemonwire-data:/data -p 8080:8080 -p 6969:6969 lemonwire-server
FROM rust:1-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p lemonwire-server \
 && cp target/release/lemonwire-server /usr/local/bin/

FROM debian:trixie-slim
RUN useradd --system --uid 10001 --home-dir /data lemonwire \
 && mkdir /data && chown lemonwire:lemonwire /data
COPY --from=build /usr/local/bin/lemonwire-server /usr/local/bin/lemonwire-server
USER lemonwire
ENV LEMONWIRE_DATA=/data \
    LEMONWIRE_BIND=0.0.0.0:8080 \
    LEMONWIRE_TRACKER_BIND=0.0.0.0:6969
VOLUME /data
EXPOSE 8080 6969
ENTRYPOINT ["lemonwire-server"]
CMD ["serve"]
