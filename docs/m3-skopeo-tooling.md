# Pinned Skopeo tooling for M3

M3 local inspection and the read-only registry verifier require a pinned
Skopeo executable. The current supported tool profile is the Rocky Linux 10
AppStream package `skopeo-3:1.24.0-2.el10`, for x86_64 and aarch64. The pin
records each architecture's official Rocky repository URL, RPM SHA-256,
executable SHA-256, and the Rocky Linux 10 release-key fingerprint.

This is a distribution trust domain for the local inspection tool. It is not
customer artifact trust, customer approval, or evidence that a Debian or RHEL
qualification host is ready. The Skopeo RPM is a dynamically linked Rocky 10
package and is not copied into the generic Helm/kubectl binary directory.

## Acquire and install

On a Rocky Linux 10 operator workstation, acquire the two architecture-specific
RPMs from the pinned official Rocky URLs and verify their RPM signatures and
digests:

```sh
python3 scripts/m3_skopeo_tool.py acquire --output /var/tmp/kordex-skopeo-rpms
```

Install the matching RPM on a Rocky Linux 10 inspection workstation:

```sh
sudo scripts/install-pinned-skopeo.sh /var/tmp/kordex-skopeo-rpms/skopeo-linux-amd64.rpm
python3 scripts/m3_skopeo_tool.py verify-runtime
python3 scripts/m3_qualification.py inspect
```

For aarch64, use `skopeo-linux-arm64.rpm`. The installer rejects other
distributions, versions, architectures, package identities, signatures,
digests, or executable builds. It installs only the supplied local RPM and
does not enable or contact package repositories. If required dependencies are
not already installed, the install fails; provision those dependencies through
the separately approved customer process.

To include Skopeo artifacts in the existing signed offline tools lock, acquire
both pinned RPMs first and set `KORDEX_OFFLINE_SKOPEO_RPM_DIR` to their
directory when running `scripts/acquire-offline-tools.sh`. The resulting lock
contains both Skopeo architectures, their package and executable digests, the
official source URLs, and the Rocky signer fingerprint. The existing Kordex
tool-lock signing key remains separately required to sign the complete lock.

The repository does not claim customer authorization for Rocky's signing key.
Customers that require their own approved-tool signer must independently
approve this upstream signing root before using the tool in a customer
qualification environment. No customer keys or signatures are stored here.
