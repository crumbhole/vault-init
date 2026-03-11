# vault-init

This is a fork of [sethvargo/vault-init](https://github.com/sethvargo/vault-init) via [liatrio/vault-init](https://github.com/liatrio/vault-init) with the following key differences:

- Root token and unseal keys are stored on the filesystem encrypted with [age](https://github.com/FiloSottile/age) instead of in a Kubernetes Secret
- Age private keys (identities) are securely stored in Kubernetes Secrets
- Designed specifically for Kubernetes environments

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
  - name: SECRET_DIR
    value: /vault/secrets
  - name: AGE_RECIPIENTS
    value: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
  - name: AGE_IDENTITIES_SECRET_NAME
    value: vault-age-identity
  - name: AGE_IDENTITIES_SECRET_KEY
    value: identity
  volumeMounts:
  - name: vault-secrets
    mountPath: /vault/secrets
volumes:
- name: vault-secrets
  emptyDir: {}
```

You can also use this alongside the official Vault Helm chart:

```yaml
server:
  extraContainers:
    - name: vault-init
      image: ghcr.io/crumbhole/vault-init:latest
      imagePullPolicy: Always
      env:
        - name: SECRET_DIR
          value: /vault/secrets
        - name: AGE_RECIPIENTS
          value: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
        - name: AGE_IDENTITIES_SECRET_NAME
          value: vault-age-identity
        - name: AGE_IDENTITIES_SECRET_KEY
          value: identity
      volumeMounts:
        - name: vault-secrets
          mountPath: /vault/secrets
  extraVolumes:
    - name: vault-secrets
      emptyDir: {}
```

## Configuration

The `vault-init` service supports the following environment variables for configuration:

- `CHECK_INTERVAL` ("10s") - The time duration between Vault health checks. Set
  this to a negative number to unseal once and exit.

- `SECRET_DIR` - The directory where the encrypted vault secrets file will be stored.
  The file will be named `vault-secrets.age` within this directory.

- `AGE_RECIPIENTS` - Comma-separated list of age public keys (recipients) that can decrypt
  the vault secrets. These are age X25519 public keys in the format `age1...`.
  You can generate a key pair using `age-keygen`.

- `AGE_IDENTITIES_SECRET_NAME` - **(Required)** Name of the Kubernetes Secret containing
  the age private key(s). The application will read the identities from this secret.
  This ensures private keys are stored securely and not exposed in deployment configurations.

- `AGE_IDENTITIES_SECRET_KEY` - The key name within the Kubernetes Secret
  that contains the age identities. Defaults to `"identities"` if not specified.

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

## Generating Age Keys

To generate an age key pair for encrypting/decrypting vault secrets:

```bash
# Install age
$ go install filippo.io/age/cmd/...@latest

# Generate a key pair
$ age-keygen
# Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
# AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYS
```

The public key (starting with `age1`) should be set as `AGE_RECIPIENTS`.
The private key (starting with `AGE-SECRET-KEY-1`) should be stored in a Kubernetes Secret.

## Setting Up Kubernetes Secret for Age Identity

For Kubernetes deployments, create a secret containing the age private key:

```bash
# Create the secret with your age private key
kubectl create secret generic vault-age-identity \
  --from-literal=identity=AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYS

# Or from a file
age-keygen -o identity.txt
kubectl create secret generic vault-age-identity \
  --from-file=identity=identity.txt
rm identity.txt  # Clean up the file after creating the secret
```

Then reference this secret in your deployment:

```yaml
env:
  - name: AGE_IDENTITIES_SECRET_NAME
    value: vault-age-identity
  - name: AGE_IDENTITIES_SECRET_KEY
    value: identity  # This is optional, defaults to "identities"
```

**Important Security Notes:**
- Store the private key (`AGE_IDENTITIES`) securely in a Kubernetes Secret, not as a plain environment variable
- You can specify multiple recipients (public keys) to allow multiple parties to decrypt the secrets
- The private key is only needed for unseal operations, not for initialization
- Consider using a volume mount for `SECRET_DIR` to persist the encrypted secrets file
- Ensure the Kubernetes Secret containing the age identity is properly secured with RBAC

## Permissions

### Kubernetes RBAC

The vault-init service needs permission to read the Kubernetes Secret containing the age identity.
The following role can be used:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vault-init-reader
rules:
  - apiGroups:
      - ""
    resourceNames:
      - vault-age-identity  # or whatever you set for AGE_IDENTITIES_SECRET_NAME
    resources:
      - secrets
    verbs:
      - get
```

Bind this role to the service account used by the vault-init container:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vault-init-reader-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: vault-init-reader
subjects:
  - kind: ServiceAccount
    name: vault  # or your vault service account name
    namespace: default
```

### Filesystem Permissions

Ensure:
- The `SECRET_DIR` directory is writable by the vault-init container
- The `SECRET_DIR` is on a persistent volume if you want secrets to survive pod restarts
- File permissions are set appropriately (the code creates files with mode 0600)

## Complete Example

Here's a complete example for deploying with the Vault Helm chart:

```yaml
# First, create the age identity secret
# kubectl create secret generic vault-age-identity --from-literal=identity=AGE-SECRET-KEY-1...

# values.yaml for Vault Helm chart
server:
  # Service account for RBAC
  serviceAccount:
    create: true
    name: vault

  extraContainers:
    - name: vault-init
      image: ghcr.io/crumbhole/vault-init:latest
      imagePullPolicy: Always
      env:
        - name: SECRET_DIR
          value: /vault/secrets
        - name: AGE_RECIPIENTS
          value: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
        - name: AGE_IDENTITIES_SECRET_NAME
          value: vault-age-identity
        - name: AGE_IDENTITIES_SECRET_KEY
          value: identity
        - name: CHECK_INTERVAL
          value: "10s"
      volumeMounts:
        - name: vault-secrets
          mountPath: /vault/secrets

  extraVolumes:
    - name: vault-secrets
      persistentVolumeClaim:
        claimName: vault-secrets-pvc  # Use PVC for persistence

---
# RBAC for reading the age identity secret
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vault-init-reader
rules:
  - apiGroups: [""]
    resourceNames: [vault-age-identity]
    resources: [secrets]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vault-init-reader-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: vault-init-reader
subjects:
  - kind: ServiceAccount
    name: vault
    namespace: default
```
