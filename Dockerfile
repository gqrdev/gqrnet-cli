FROM golang:1.27.1-trixie

RUN groupadd -g 1000 devuser \
    && useradd -m -u 1000 -g devuser devuser

RUN mkdir -p /go/pkg/mod \
    && mkdir -p /go/pkg/sumdb \
    && chown -R devuser:devuser /go/pkg

ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH="${GOROOT}/bin:${GOPATH}/bin:${PATH}"

USER devuser
WORKDIR /workspace

