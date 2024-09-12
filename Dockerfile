FROM golang:1.23 AS builder

RUN apt-get -qq update

ENV GO111MODULE=on \
  CGO_ENABLED=0 

WORKDIR /src

COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH\
  go build \
  -a \
  -trimpath \
  -ldflags "-s -w -extldflags '-static'" \
  -tags 'osusergo netgo static_build' \
  -o /bin/vault-init \
  .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/vault-init /bin/vault-init
CMD ["/bin/vault-init"]
