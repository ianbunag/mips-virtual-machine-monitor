# MIPS Virtual Machine Monitor (VMM)

A user-space virtual machine monitor and hypervisor written in C, featuring MIPS instruction emulation, round-robin multi-VM scheduling, state snapshotting, and TCP-based live migration across host systems.

> **Context:** Graduate Research Project — **CMPE-283: Virtual Technologies** (Fall 2026)  
> **Researcher:** [John Ian Buñag](https://github.com/ianbunag)  
> **Core Engine:** [myvmm.c](./project/myvmm.c)  
> **Infrastructure & Tooling:** [Terraform Cloud Lab](./terraform/) | [Ansible Automation](./ansible/)

## Prerequisites

### 1. Generate Deploy Key

Generate a dedicated ED25519 SSH key pair for the VM deploy key:

```bash
ssh-keygen -t ed25519 -C "cmpe-283.ianbunag.dev" -f ./id_ed25519_cmpe-283-ianbunag-dev
```

### 2. Add Deploy Key to GitHub Repository

Add the generated public key (`./id_ed25519_cmpe-283-ianbunag-dev.pub`) to the GitHub repository's deploy keys:

- Refer to the [GitHub Deploy Keys Documentation](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys#set-up-deploy-keys).
- **Title**: Value of `deploy_key_secret_name` in [terraform/locals.tf](terraform/locals.tf)
- **Key**: Contents of `./id_ed25519_cmpe-283-ianbunag-dev.pub`

### 3. Create GCP Secret Manager Secret

Store the private key in Google Cloud Secret Manager:

- **Name**: Value of `deploy_key_secret_name` in [terraform/locals.tf](terraform/locals.tf)
- **Secret value**: Contents of `./id_ed25519_cmpe-283-ianbunag-dev` (the private key)
- **Replication policy**:
  - **Manually manage locations for this secret**: Enabled
  - **Location(s)**: `us-west1`

## Terraform Lab Provisioning

This repository's [`terraform/`](./terraform/) directory is designed as a reusable module to provision the virtualized research environment on Google Cloud Platform with Cloudflare DNS management:

```hcl
provider "cloudflare" {
  api_token = ""
}

provider "google" {
  project               = ""
  region                = "us-west1"
  zone                  = "us-west1-b"
  user_project_override = true
}

module "mips-virtual-machine-monitor" {
  source = "git@github.com:ianbunag/mips-virtual-machine-monitor.git//terraform"
  root_domain                             = ""
  cloudflare_update_dns_token_secret_name = ""
  cloudflare_zone_id                      = ""
  ssh_public_key_file                     = ""
  ssh_username                            = ""
}
```

## Remote Development

### CLion Deployment Configuration

You can configure CLion for remote development via SFTP file synchronization using JetBrains' built-in deployment tooling. For general reference, see the [CLion Deployment Settings Documentation](https://www.jetbrains.com/help/clion/settings-deployment.html).

1. In CLion, navigate to **Tools** > **Deployment** > **Configuration...**.
2. Click **+** to add a new server configuration.

#### Connection Settings

| Setting | Value |
| :--- | :--- |
| **Type** | `SFTP` |
| **Root path** | `/home/<username>/Documents/remote-cmpe-283-virtual-technologies` |
| **Use rsync for download/upload/sync** | Enabled |

#### Mappings

Switch to the **Mappings** tab:

| Setting | Value |
| :--- | :--- |
| **Local path** | `<project-root>` |
| **Deployment path** | `/` |

### Enabling IntelliSense

To activate code completion and IntelliSense in CLion:

1. Open the source file containing the `main` function.
2. Click the green **Run** (play) button in the editor gutter beside `main`.

This allows CLion to resolve the execution context and index project symbols, enabling full code navigation, diagnostics, and auto-completion.

## Running Lint and Tests

### 1. SSH Configuration

Add the host entry to your `~/.ssh/config`:

```ssh-config
Host cmpe-283
    HostName cmpe-283.<root-domain>
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    RequestTTY yes
    RemoteCommand cd ~/Documents/remote-cmpe-283-virtual-technologies && exec $SHELL -l
```

### 2. Connect to the Remote VM

Connect directly via SSH:

```bash
ssh cmpe-283
```

Navigate into the project directory:

```bash
cd project
```

### 3. Run Lint (SAST & DAST)

Compiles the hypervisor, performs static analysis via `flawfinder`, and executes dynamic memory leak checking via `valgrind`:

```bash
./run-lint.sh
```

### 4. Run Tests

Builds the binary and runs the complete automated regression test suite:

```bash
./run-tests.sh
```

## Hypervisor Usage & Concurrency

`myvmm` is an instruction-emulating user-space hypervisor capable of managing multiple concurrent virtual machines using round-robin scheduling, instruction execution slicing, checkpoint snapshotting, and TCP-based live migration.

### Command-Line Arguments

```text
Usage: ./myvmm [-v <config_file>] [-s <snapshot_file>] [-n <slice>] [-p <port>] [-t <timeout>] [-d]
```

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `-v` | `<file>` | Path to virtual machine configuration file. May be specified multiple times to launch multiple VMs concurrently. |
| `-s` | `<file>` | Path to a snapshot file to restore the preceding `-v` VM's state prior to execution. |
| `-n` | `<positive_int>` | Global instruction execution slice. Slices execution across all VMs in round-robin fashion (overrides per-VM configuration). |
| `-p` | `<port>` | Port (1024–65535) for the migration TCP server listener. |
| `-t` | `<seconds>` | Migration server idle timeout in seconds before closing when no VMs are running. |
| `-d` | _none_ | Enable verbose debug logging to stderr. |

### VM Configuration File Format

Each VM passed via `-v` is configured using key-value pairs (`key=value`):

```ini
# Path to file containing MIPS assembly / instructions
vm_binary=tests/instruction_slice_vm1_instructions

# (Optional) Execution slice quantum specific to this VM
vm_exec_slice_in_instructions=2
```

### Scheduling & Concurrency Semantics

- **Round-Robin Scheduling**: When multiple `-v` VMs are configured, the hypervisor enqueues them into an active queue and context-switches among them in round-robin order.
- **Slice Resolution Hierarchy**:
  1. **CLI Flag `-n <slice>`**: If specified, overrides all VMs with a global quantum.
  2. **Config Parameter `vm_exec_slice_in_instructions`**: If `-n` is omitted, each VM follows its own configured slice.
  3. **Unbounded (Default)**: If neither is defined, the VM executes uninterrupted until completion or migration.
- **Instruction Counting**: Every valid executed line (standard MIPS instructions as well as para-instructions like `DUMP_PROCESSOR_STATE`, `DUMP_REGISTER_STATE`, and `SNAPSHOT`) advances the slice count by 1. Blank lines are skipped without incrementing.
- **Migration & Slicing**: When a VM migrates over the network, the target hypervisor’s global `-n` flag takes precedence if set; otherwise, the migrated VM preserves its original per-VM execution slice.

### Example Invocations

Run two concurrent VMs with a global slice of 10 instructions per turn:
```bash
./myvmm -n 10 -v assembly_file_vm1 -v assembly_file_vm2
```

Run multiple VMs using their individual configuration slices with debug logging enabled:
```bash
./myvmm -d -v tests/individual_slice_lower_assembly_file -v tests/individual_slice_higher_assembly_file
```

Run concurrent VMs with snapshot restoration and an incoming migration listener on port 9088:
```bash
./myvmm -d -p 9088 -t 5 -n 2 -v tests/complete_feature_set_vm1_assembly_file -s tests/complete_feature_set_vm1_snapshot -v tests/complete_feature_set_vm2_assembly_file
```

