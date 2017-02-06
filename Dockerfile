FROM alpine:3.4

RUN apk add -U iptables
ADD ./bin/networkBlocker-linux-amd64 /app/networkBlocker

EXPOSE 8086

ENTRYPOINT ["/app/networkBlocker"]