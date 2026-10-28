# Tilde Runner deployment

Public deployment configuration and measured-release workflows for Tilde Runner.
The Rust application source and image-build workflow remain in the private
`tildeapp/tilde` repository. The image is published privately to
`ghcr.io/tildeapp/tilde-runner`.

## Boot experiment

The RAM-backed configuration runs the hosted service with disposable
installation credentials released by our keyserver at `https://keys.tildeapp.ai`. It exposes
health, public identity, activation, authenticated commands, and encrypted
progress streams.

This configuration uses a RAM-backed state directory. Stopping or replacing the
container loses its installation keys and unfinished work. Use only disposable
accounts and data. This configuration does not provide persistent enrollment,
durable key recovery or the complete hosted chat migration. Private delivery
requires the keyserver to approve the exact repository, release tag, and domain.
Deployment is not approval to release household keys.

Generate `TILDE_RUNNER_CONFIG` and the volume secret `TILDE_RUNNER_DISK_KEY` on the
customer-controlled keyserver. The first contains the hosted runner configuration. The
runner's keys are not released by the keyserver: since TDE-514 the runner generates its
host root inside the enclave on first boot, keeps it only on the encrypted volume, and
refuses to start if the volume or the root is missing later. `TINFOIL_API_KEY`, the
inference provider key the runner uses to call the model directly, is stored on
the keyserver and released the same way; Tinfoil rejects a deployment that mixes
its managed secrets with keyserver delivery. Keep these values out of
this repository, GitHub Actions, command-line arguments, and Tinfoil-managed
secret storage. When updating an older instance, explicitly clear its managed
secret selections with `--secret=""`. The private source repository defines the
configuration schema. The keyserver is contacted by the enclave bootstrap; the
application itself has no need for keyserver egress.

Configure read-only GHCR credentials in Tinfoil before deployment. The minimum
measured allocation is two CPUs and 8192 MB RAM. The process runs as an
unprivileged user with a read-only root and a bounded writable `/state` tmpfs.

## Release procedure

1. In the private source repository, run **Publish Private Runner Image** against
   the reviewed source revision, or push a `runner-image-*` tag. The workflow runs
   the Docker build/tests and publishes a Linux amd64 image. Confirm package
   visibility is private and copy the immutable image reference from its summary.
2. Update and review `tinfoil-config.yml`. Keep credentials, private keys,
   account/family identifiers, and application source out of this repo.
   Secret names and image digests are public; secret values are not configuration.
3. Run **Tinfoil Release** on the reviewed commit with a new version. It creates a
   tag and dispatches **Tinfoil Release - Publish** on that tag. Wait for a
   successful GitHub release containing the deployment manifest and measurement.
   Creating a tag alone is insufficient.
   Mark the new approved release as GitHub's latest release before booting it:
   `gh release edit <tag> --repo tildeapp/tilde-runner --latest`.
   Tinfoil automatically publishes freshness witnesses for the latest release;
   an unpublished witness prevents private-secret delivery. Client and keyserver
   trust policies still pin the exact tag and approved measurement, not `latest`.
4. Deploy that exact release using the Tinfoil dashboard or CLI. Leave debug and
   confidential-computing bypass disabled.
5. Verify the deployed endpoint against the expected repository and exact release
   using the Tinfoil SDK or CLI. An ordinary HTTPS health response is not evidence
   of attestation. Pin the approved measurement in client and keyserver policy
   before granting access to user keys or data.

Image publication and deployment release are separate, explicit operations. This
repository does not check out the private source or need a private-source token.
Public attestation pins an image; it does not make that image's source auditable.

## Upstream references

Workflows follow the [Tinfoil template](https://github.com/tinfoilsh/tinfoil-containers-template/tree/0eddc320b8f328d7a3c057152596934444ac2d75),
with commit-pinned actions and release preflight checks.

- [Configuration](https://docs.tinfoil.sh/containers/configuration)
- [Private images and registry credentials](https://docs.tinfoil.sh/containers/private-images)
- [Private secrets](https://docs.tinfoil.sh/containers/private-secrets)
