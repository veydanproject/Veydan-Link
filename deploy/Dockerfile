# The bridge as an image:  make image
#
#   docker run -d --name vlink --restart=unless-stopped \
#     -p 443:443 -v vlink:/data veydan/vlink
#
# The image holds one static binary, its licence and the notices of the
# crates it is built from, nothing else: no shell, no system. /data keeps
# the bridge's certificate; with the volume gone, the bridge comes back as
# another bridge.
FROM scratch
LABEL org.opencontainers.image.title="VLink" \
      org.opencontainers.image.description="The VLink bridge: carries Veydan traffic past a throttled border" \
      org.opencontainers.image.vendor="Veydan Project" \
      org.opencontainers.image.authors="Veydan Project" \
      org.opencontainers.image.licenses="LicenseRef-PolyForm-Perimeter-1.0.1" \
      org.opencontainers.image.source="https://github.com/veydanproject/Veydan-Link"
# PolyForm Perimeter 1.0.1: whoever gets the image gets the terms with it.
COPY LICENSE /LICENSE
# The notices of the crates the binary is built from.
COPY THIRD-PARTY-LICENSES.md /THIRD-PARTY-LICENSES.md
COPY dist/vlink /vlink
ENV VLINK_DATA=/data VLINK_LISTEN=0.0.0.0:443
VOLUME /data
EXPOSE 443
ENTRYPOINT ["/vlink"]
