FROM public.ecr.aws/amazonlinux/amazonlinux:2023

RUN dnf install -y ca-certificates openssl shadow-utils \
  && dnf clean all \
  && useradd --system --uid 10001 --gid 0 a402

COPY bin/a402-enclave /opt/a402/bin/a402-enclave
COPY entrypoint.sh /opt/a402/bin/entrypoint.sh
COPY etc/a402/enclave.env /etc/a402/enclave.env
COPY tls/ /etc/a402/tls/

RUN chmod 0755 /opt/a402/bin/a402-enclave /opt/a402/bin/entrypoint.sh \
  && chmod 0600 /etc/a402/tls/* \
  && mkdir -p /var/lib/a402

ENTRYPOINT ["/opt/a402/bin/entrypoint.sh"]
