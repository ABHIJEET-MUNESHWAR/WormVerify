# WormVerify — reproducible on-chain program build.
#
# Produces the verifiable BPF/SBF artifact of the wormverify-core program using
# the Anchor toolchain. The resulting `.so` can be checksummed against a
# mainnet deployment for a verified build.

FROM backpackapp/build:v0.30.1 AS build
WORKDIR /workdir
COPY anchor/ anchor/
WORKDIR /workdir/anchor
RUN anchor build

FROM debian:bookworm-slim AS artifact
WORKDIR /out
COPY --from=build /workdir/anchor/target/deploy/*.so ./
COPY --from=build /workdir/anchor/target/idl/*.json ./
CMD ["sh", "-c", "ls -l /out && sha256sum /out/*.so"]
