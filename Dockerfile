FROM alpine:latest

ARG TARGETARCH
ARG TARGETVARIANT

COPY dist/stmp2log_${TARGETARCH}${TARGETVARIANT} /usr/bin/stmp2log
COPY docker-init.sh /init.sh

RUN apk add --no-cache tzdata \
	&& chmod 0755 /usr/bin/stmp2log /init.sh \
	&& stmp2log -v

ENV TZ=Asia/Shanghai

EXPOSE 25 465 8025

WORKDIR /data

CMD ["/init.sh"]
