# syntax=docker/dockerfile:1.3

FROM alpine:3.15
RUN apk add --no-cache ca-certificates
COPY config-dev.yml /etc/docker/registry/config.yml
COPY registry /bin/registry
VOLUME ["/var/lib/registry"]
EXPOSE 5000
ENTRYPOINT ["registry"]
CMD ["serve", "/etc/docker/registry/config.yml"]
