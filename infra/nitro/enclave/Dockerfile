FROM public.ecr.aws/amazonlinux/amazonlinux:2023

RUN dnf install -y ca-certificates openssl shadow-utils \
  && dnf clean all \
  && useradd --system --uid 10001 --gid 0 subly402

COPY bin/subly402-enclave /opt/subly402/bin/subly402-enclave
COPY entrypoint.sh /opt/subly402/bin/entrypoint.sh
COPY etc/subly402/enclave.env /etc/subly402/enclave.env
COPY tls/ /etc/subly402/tls/

RUN chmod 0755 /opt/subly402/bin/subly402-enclave /opt/subly402/bin/entrypoint.sh \
  && chmod 0600 /etc/subly402/tls/* \
  && mkdir -p /var/lib/subly402

ENTRYPOINT ["/opt/subly402/bin/entrypoint.sh"]
