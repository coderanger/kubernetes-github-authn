FROM scratch
ADD https://curl.haxx.se/ca/cacert.pem /etc/ssl/certs/
COPY _output/main.linux /boot
CMD ["/boot"]
