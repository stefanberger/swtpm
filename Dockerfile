FROM python:3.9-alpine3.19 AS builder

LABEL org.opencontainers.image.authors="Stefan Berger"

ENV PACKAGES="curl openssl-dev automake autoconf bash build-base libtool make socat gawk libtasn1-dev gnutls gnutls-utils gnutls-dev expect libseccomp-dev softhsm py3-cryptography py3-twisted py3-setuptools json-glib-dev gmp-dev"
RUN apk add --no-cache --no-check-certificate $PACKAGES && rm -rf /var/cache/apk/*

ARG LIBTPMS_BRANCH=master
WORKDIR /src/build-prep/libtpms
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN curl -kL "https://github.com/stefanberger/libtpms/archive/${LIBTPMS_BRANCH}.tar.gz" \
      | tar --strip=1 -zxvf - -C /src/build-prep/libtpms

RUN ./autogen.sh --prefix=/usr --libdir=/usr/lib --with-tpm2 --with-openssl \
    && make -j"$(nproc)" V=1 \
    && make -j"$(nproc)" V=1 check \
    && make -j"$(nproc)" install \
    && make DESTDIR=/app -j"$(nproc)" install

COPY . /src/build-prep/swtpm
WORKDIR /src/build-prep/swtpm
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN ./autogen.sh --prefix=/usr --libdir=/usr/lib --with-openssl --with-tss-user=root --with-tss-group=root \
    && make -j"$(nproc)" V=1 \
    && echo "softhsm or certtool are crashing pkcs11 test case" \
    && { for f in test_tpm2_swtpm_localca_pkcs11.test test_tpm2_samples_swtpm_localca_pkcs11; do echo -en '#!/usr/bin/env bash'"\nexit 77\n" > tests/${f}; done; } \
    && make -j"$(nproc)" V=1 VERBOSE=1 check \
    && make DESTDIR=/app -j"$(nproc)" install

FROM alpine:3.19

LABEL org.opencontainers.image.authors="Stefan Berger"

ENV PACKAGES="openssl socat gawk libtasn1 expect libseccomp softhsm py3-cryptography py3-twisted py3-setuptools json-glib gmp"
RUN apk add --no-cache --no-check-certificate $PACKAGES && rm -rf /var/cache/apk/*

COPY --from=builder /app /

WORKDIR /app

ENTRYPOINT ["/usr/bin/swtpm"]
