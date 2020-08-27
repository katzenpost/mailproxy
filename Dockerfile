FROM golang:alpine AS builder

# Can pass --build-arg warped=true to decrease epoch period
ARG warped=false

# Install git & make
# Git is required for fetching the dependencies
RUN apk update && \
    apk add --no-cache git make ca-certificates && \
    update-ca-certificates

# Set the working directory for the container
WORKDIR /go/mailproxy

# Build the binary
COPY . .
RUN cd cmd/mailproxy && go build

FROM alpine

RUN apk update && \
    apk add --no-cache ca-certificates tzdata && \
    update-ca-certificates

COPY --from=builder /go/mailproxy/cmd/mailproxy/mailproxy /go/bin/mailproxy

# create a volume for the configuration persistence
VOLUME /conf

# This form of ENTRYPOINT allows the process to catch signals from the `docker stop` command
ENTRYPOINT ["/go/bin/mailproxy", "-f", "/conf/mailproxy.toml"]
CMD ["tail", "-f", "/conf/mailproxy/mailproxy.log"]
