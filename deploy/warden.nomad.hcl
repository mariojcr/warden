# SPDX-FileCopyrightText: 2026 Mario Campos <https://github.com/mariojcr>
# SPDX-License-Identifier: Apache-2.0

# An example Nomad job for warden. Two listeners on the host network, both with TLS: the browser one
# (the owner's panel and approval pages, behind a reverse proxy) and the API one (agents and the
# companion app). Secrets come from the Nomad variable nomad/jobs/<name>:
#   master_key, oidc_client_secret, heimdall_token, tls_cert, tls_key, nomad_ca, google_client_secret
# The master key must not live on the data volume: the audit chain is keyed from it.

variable "name" {
  type    = string
  default = "warden"
}

variable "image" {
  type = string
}

variable "listen_ip" {
  type = string
}

variable "domain" {
  type = string
}

variable "browser_port" {
  type    = number
  default = 8780
}

variable "api_port" {
  type    = number
  default = 8781
}

variable "issuer" {
  type = string
}

variable "oidc_client_id" {
  type = string
}

# The owner's `sub` at the identity provider
variable "owner_sub" {
  type = string
}

# A GitHub OAuth App (device flow, no client secret) and the login its token must belong to
variable "github_client_id" {
  type = string
}

variable "github_login" {
  type = string
}

variable "nomad_jwks_url" {
  type = string
}

# Jobs in the default namespace that may open a session, and jobs in other namespaces
variable "claude_jobs" {
  type    = list(string)
  default = ["claude"]
}

variable "claude_other_namespaces" {
  type    = map(list(string))
  default = {}
}

variable "webauthn_rp_id" {
  type    = string
  default = ""
}

variable "heimdall_origin" {
  type    = string
  default = ""
}

variable "heimdall_android_origin" {
  type    = string
  default = ""
}

variable "claude_email" {
  type    = string
  default = ""
}

variable "claude_max_grant_secs" {
  type    = number
  default = 2592000
}

variable "gcp_client_id" {
  type    = string
  default = ""
}

variable "gcp_email" {
  type    = string
  default = ""
}

# What can be requested, by preset: exact images and packages (src/registry.rs, `Artifact`)
variable "gcp_presets" {
  type = map(object({ description = string, artifacts = list(string) }))
  default = {
    app-env = {
      description = "Images and packages to build the app"
      artifacts = [
        "europe-docker.pkg.dev/example-project/images/app",
        "europe-west1-npm.pkg.dev/example-project/npm/@example/ui",
      ]
    }
  }
}

variable "gcp_other_namespaces" {
  type    = map(list(string))
  default = {}
}

variable "data_volume" {
  type    = string
  default = "warden-data"
}

locals {
  vars = "nomad/jobs/${var.name}"
  config = {
    data_dir            = "/data"
    browser_listen      = "${var.listen_ip}:${var.browser_port}"
    api_listen          = "${var.listen_ip}:${var.api_port}"
    tls                 = { cert = "/secrets/tls.crt", key = "/secrets/tls.key" }
    public_url          = "https://${var.domain}"
    master_key_file     = "/secrets/master.key"
    heimdall_token_file = "/secrets/heimdall.token"
    oidc = {
      issuer             = var.issuer
      client_id          = var.oidc_client_id
      client_secret_file = "/secrets/oidc.secret"
      owner_sub          = var.owner_sub
    }
    github = {
      client_id      = var.github_client_id
      scopes         = ["repo"]
      expected_login = var.github_login
    }
    nomad = {
      jwks_url         = var.nomad_jwks_url
      ca_file          = "/secrets/nomad-ca.pem"
      jobs             = var.claude_jobs
      other_namespaces = { for ns in distinct(concat(keys(var.claude_other_namespaces), keys(var.gcp_other_namespaces))) : ns => distinct(concat(lookup(var.claude_other_namespaces, ns, []), lookup(var.gcp_other_namespaces, ns, []))) }
    }
    webauthn = var.webauthn_rp_id == "" ? null : {
      rp_id            = var.webauthn_rp_id
      heimdall_origins = [for o in [var.heimdall_origin, var.heimdall_android_origin] : o if o != ""]
    }
    claude = var.claude_email == "" ? null : {
      expected_email = var.claude_email
      max_grant_secs = var.claude_max_grant_secs
    }
    gcp = var.gcp_client_id == "" ? null : {
      client_id          = var.gcp_client_id
      client_secret_file = "/secrets/google.secret"
      expected_email     = var.gcp_email
      presets            = var.gcp_presets
    }
  }
}

job "warden" {
  type = "service"

  group "warden" {
    restart {
      attempts = 5
      interval = "30m"
      delay    = "10s"
      mode     = "delay"
    }
    reschedule {
      attempts  = 0
      unlimited = false
    }

    network {
      mode = "host"
      port "browser" {
        static = var.browser_port
      }
      port "api" {
        static = var.api_port
      }
    }

    service {
      provider     = "nomad"
      name         = var.name
      port         = "browser"
      address_mode = "host"
    }

    volume "data" {
      type   = "host"
      source = var.data_volume
    }

    # The database belongs to the image user (10001)
    task "prepare" {
      lifecycle {
        hook = "prestart"
      }
      driver = "podman"
      user   = "root"
      volume_mount {
        volume      = "data"
        destination = "/data"
      }
      config {
        image      = var.image
        force_pull = false
        entrypoint = ["/bin/sh", "-c"]
        args       = ["chown -R 10001:10001 /data && chmod 700 /data"]
      }
      resources {
        cpu    = 50
        memory = 32
      }
    }

    task "warden" {
      driver       = "podman"
      kill_timeout = "10s"

      volume_mount {
        volume      = "data"
        destination = "/data"
      }

      config {
        image        = var.image
        force_pull   = false
        network_mode = "host"
        args         = ["serve", "--config", "/local/warden.json"]
      }

      template {
        destination     = "local/warden.json"
        data            = jsonencode(local.config)
        left_delimiter  = "[[["
        right_delimiter = "]]]"
      }

      dynamic "template" {
        for_each = {
          "master.key"     = "master_key"
          "oidc.secret"    = "oidc_client_secret"
          "heimdall.token" = "heimdall_token"
          "tls.crt"        = "tls_cert"
          "tls.key"        = "tls_key"
          "nomad-ca.pem"   = "nomad_ca"
          "google.secret"  = "google_client_secret"
        }
        content {
          destination = "secrets/${template.key}"
          perms       = "0400"
          uid         = 10001
          gid         = 10001
          data        = "{{ with nomadVar \"${local.vars}\" }}{{ .${template.value}.Value }}{{ end }}"
        }
      }

      resources {
        cpu        = 200
        memory     = 64
        memory_max = 256
      }
    }
  }
}
