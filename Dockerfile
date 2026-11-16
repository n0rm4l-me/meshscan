# syntax=docker/dockerfile:1

# Build on the host platform and cross-compile, so multi-arch images need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=
ARG DATE=
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w \
        -X github.com/n0rm4l-me/meshscan/internal/version.Version=${VERSION} \
        -X github.com/n0rm4l-me/meshscan/internal/version.Commit=${COMMIT} \
        -X github.com/n0rm4l-me/meshscan/internal/version.Date=${DATE}" \
      -o /out/meshscan ./cmd/meshscan

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="meshscan" \
      org.opencontainers.image.description="Audit Istio service mesh configuration for common misconfigurations" \
      org.opencontainers.image.source="https://github.com/n0rm4l-me/meshscan" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/meshscan /usr/local/bin/meshscan
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/meshscan"]
