#!/usr/bin/env node
// TODO(Track B): Embed soma-release-manifest.json into the package root at
// build time. The manifest contains the full UpdateCertificate for this
// version, enabling offline provenance verification.
//
// Flow:
//   1. Read the UpdateCertificate from the ceremony co-sign response.
//   2. Write it as `soma-release-manifest.json` in the package root.
//   3. Include the manifest in the tarball (add to package.json `files`).
//
// The heart reads this manifest on startup to populate packageProvenance
// in its BirthCertificates. See §3.4 of the update-certificate proposal.

throw new Error('embed-release-manifest: not yet implemented — waiting for Track B integration');
