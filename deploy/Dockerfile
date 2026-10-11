# The bridge as an image:  make image
#
#   docker run -d --name vlink --restart=unless-stopped \
#     -p 443:443 -v vlink:/data rookbeam/vlink
#
# The image holds two static binaries, their licence and the notices of the
# crates they are built from, nothing else: no shell, no system. /data keeps
# the bridge's key (its id), its TLS key and the certificate chain; with
# the volume gone, the bridge comes back as another bridge.
#
# The second binary is the agent of the project's monitoring, off unless the
# volunteer turns it on (-e VEYDAN_AGENT=on, README.md, "Project
# monitoring"). It is the first process: without the switch it hands the
# process over to the bridge at once, so the bridge runs exactly as alone.
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
# The agent: the image build takes it from the kit of the project's
# servers (make image VAGENT=<file>; the release passes the build of each
# architecture).
COPY dist/vagent /vagent
ENV VLINK_DATA=/data VLINK_LISTEN=0.0.0.0:443
VOLUME /data
EXPOSE 443
ENTRYPOINT ["/vagent", "entrypoint", "/vlink"]
