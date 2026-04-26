# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

WORKDIR /src

ARG TARGETOS
ARG TARGETARCH

COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod \
	go mod download

COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
	go build -trimpath -ldflags="-s -w" -o /out/scrubd ./cmd/scrubd

FROM scratch

COPY --from=build /out/scrubd /scrubd

ENTRYPOINT ["/scrubd"]
CMD ["scan"]
