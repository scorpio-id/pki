FROM golang:1.19.8 as builder
WORKDIR /workspace

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o scorpio-pki cmd/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM alpine:latest

RUN apk update
WORKDIR /

# Add configuration files
ADD /internal/config/local.yml /internal/config/local.yml

# Add swagger files
ADD /docs/swagger.json /docs/swagger.json
ADD /docs/swagger.yaml /docs/swagger.yaml

COPY --from=builder /workspace/scorpio-pki .

# the command to start the application
ENTRYPOINT ["/scorpio-pki"]