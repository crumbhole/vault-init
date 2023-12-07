# vault-init

This is a fork of [sethvargo/vault-init](https://github.com/sethvargo/vault-init) via liatrio with the following key differences:

- Root token and unseal keys are stored within a Kubernetes Secret instead of Google Cloud Storage, and completely unencrypted

## Usage

The `vault-init` service is designed to be run alongside a Vault server and
communicate over local host.

You can download the code and compile the binary with Go. Alternatively, a
Docker container is available via the Docker Hub:

```text
$ docker pull ghcr.io/crumbhole/vault-init
```

To use this as part of a Kubernetes Vault Deployment:

```yaml
containers:
- name: vault-init
  image: ghcr.io/crumbhole/vault-init:latest
  imagePullPolicy: Always
  env:
  - name: K8S_SECRET_NAME
    value: my-k8s-secret
```

You can also use this alongside the official Vault Helm chart:

```yaml
server:
  extraContainers:
    - name: vault-init
      image: ghcr.io/crumbhole/vault-init:latest
      imagePullPolicy: Always
      env:
        - name: K8S_SECRET_NAME
          value: my-k8s-secret
```

## Configuration

The `vault-init` service supports the following environment variables for configuration:

- `CHECK_INTERVAL` ("10s") - The time duration between Vault health checks. Set
  this to a negative number to unseal once and exit.

- `K8S_SECRET_NAME` - The Kubernetes secret where the Vault master key
  and root token is stored. The secret will be created in the same namespace as the Vault server pod.

- `VAULT_SECRET_SHARES` (5) - The number of human shares to create.

- `VAULT_SECRET_THRESHOLD` (3) - The number of human shares required to unseal.

- `VAULT_AUTO_UNSEAL` (true) - Use Vault 1.0 native auto-unsealing directly. You must
  set the seal configuration in Vault's configuration.

- `VAULT_STORED_SHARES` (1) - Number of shares to store on KMS. Only applies to
  Vault 1.0 native auto-unseal.

- `VAULT_RECOVERY_SHARES` (1) - Number of recovery shares to generate. Only
  applies to Vault 1.0 native auto-unseal.

- `VAULT_RECOVERY_THRESHOLD` (1) - Number of recovery shares needed to trigger an auto-unseal.
  Only applies to Vault 1.0 native auto-unseal.

- `VAULT_SKIP_VERIFY` (false) - Disable TLS validation when connecting. Setting
  to true is highly discouraged.

- `VAULT_CACERT` ("") - Path on disk to the CA _file_ to use for verifying TLS
  connections to Vault.

- `VAULT_CAPATH` ("") - Path on disk to a directory containing the CAs to use
  for verifying TLS connections to Vault. `VAULT_CACERT` takes precedence.

- `VAULT_TLS_SERVER_NAME` ("") - Custom SNI hostname to use when validating TLS
  connections to Vault.

### IAM &amp; Permissions

The Kubernetes service account for Vault needs to be able to create secrets, and read/update the desired secret
if it already exists.  The following role can be used:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vault-credentials-manager
rules:
  - apiGroups:
      - ""
    resourceNames:
      - vault-credentials # or whatever you set for the `K8S_SECRET_NAME` env var
    resources:
      - secrets
    verbs:
      - '*'
  - apiGroups:
      - ""
    resources:
      - secrets
    verbs:
      - create
```
