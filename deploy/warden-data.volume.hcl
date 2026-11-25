# SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
# SPDX-License-Identifier: Apache-2.0

# warden's database (warden.sqlite): encrypted connections, sessions, requests, grants and the audit
# chain. No plaintext secrets: the master key comes from a Nomad variable.
#   nomad volume create deploy/warden-data.volume.hcl
type      = "host"
name      = "warden-data"
plugin_id = "mkdir"

capability {
  access_mode     = "single-node-writer"
  attachment_mode = "file-system"
}
