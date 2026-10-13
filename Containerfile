ARG VERSION=2

FROM docker.io/caddy:${VERSION}-builder AS builder
RUN xcaddy build \
  --with github.com/haatveit/caddy-ecs-encoder

FROM docker.io/caddy:${VERSION}
COPY --from=builder /usr/bin/caddy /usr/bin/caddy

