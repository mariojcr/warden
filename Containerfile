# SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
# SPDX-License-Identifier: Apache-2.0

# Only the binary: secrets arrive in /secrets from Nomad and state lives on the data volume.
#   podman build -t warden .
FROM docker.io/library/rust:1.100-slim-trixie@sha256:4b68057dc8c103af4fa66b5cd29f21b18afec79fadfcd8fb91e295e939f0690c AS build
WORKDIR /src
# Dependencies first, in their own layer, so a change in src/ does not rebuild them.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && touch src/lib.rs && cargo build --release --locked && rm -rf src
COPY src src
COPY static static
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

FROM docker.io/library/debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392
# Only ca-certificates: warden never starts other processes.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin warden
COPY --from=build /src/target/release/warden /usr/local/bin/warden
ENV RUST_LOG=info
USER 10001
ENTRYPOINT ["/usr/local/bin/warden"]
CMD ["serve", "--config", "/local/warden.json"]
