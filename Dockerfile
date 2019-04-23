FROM golang:1 as builder

# Copy in the go src
COPY . /go/src/github.com/coderanger/kubernetes-github-authn
WORKDIR /go/src/github.com/coderanger/kubernetes-github-authn

RUN curl https://glide.sh/get | sh && \
    glide install && \
    CGO_ENABLED=0 go build -a -installsuffix cgo -o _output/main main.go github.go

FROM busybox
ADD https://curl.haxx.se/ca/cacert.pem /etc/ssl/certs/
COPY manifests/webhook-config.yml /
COPY --from=builder /go/src/github.com/coderanger/kubernetes-github-authn/_output/main /boot
CMD ["/boot"]
