# syntax=docker/dockerfile:1

ARG BASE_IMAGE=hashicorp/vault:2.1.2

FROM ${BASE_IMAGE}

USER root

ARG TARGETARCH
COPY docker/dist/${TARGETARCH}/vault-plugin-secrets-xai /vault/plugins/vault-plugin-secrets-xai
COPY docker/dist/${TARGETARCH}/vault-plugin-secrets-xai.sha256 /vault/plugins/vault-plugin-secrets-xai.sha256
COPY docker/plugins.hcl /vault/config/plugins.hcl

RUN mkdir -p /vault/plugins/tmp \
    && chown -R vault:vault /vault/plugins /vault/config/plugins.hcl \
    && chmod 0755 /vault/plugins/vault-plugin-secrets-xai \
    && chmod 0750 /vault/plugins /vault/plugins/tmp \
    && chmod 0644 /vault/plugins/vault-plugin-secrets-xai.sha256 \
    && chmod 0640 /vault/config/plugins.hcl

USER vault
