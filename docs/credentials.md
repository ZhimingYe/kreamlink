# Credentials on shared hosts

| Credential | Environment variable (preferred) | YAML file reference | Who needs it |
| --- | --- | --- | --- |
| Hub registration password | `KREAMLINK_HUB_PASSWORD` | `hub_password_file` | Hub, Receiver, and Sender |
| Channel secret | `KREAMLINK_CHANNEL` | `channel_file` | Receiver and Sender for that channel |

Use a different random value for each credential. Give each tenant its own OS account. File permissions and environment variables provide limited protection from other processes running as the same user or from the host administrator.

Use verified WSS even on loopback when tenants share a network namespace. A loopback port alone does not identify its owner. When HTTPS terminates outside the Hub, the deployment is responsible for protecting the remaining hop.

## Environment variables

For a service, inject the values through your service manager or secret manager. For an interactive Bash session, the following prompts read from the terminal with echo disabled. Only the commands enter shell history. Run the first prompt for all three roles and the second only for the two agents. Enter the same value wherever a credential is shared.

```bash
set +x
IFS= read -r -s -p 'Hub password: ' KREAMLINK_HUB_PASSWORD && export KREAMLINK_HUB_PASSWORD
printf '\n'
```

```bash
IFS= read -r -s -p 'Channel secret: ' KREAMLINK_CHANNEL && export KREAMLINK_CHANNEL
printf '\n'
```

Start kreamlink directly, for example with `./kreamlink -c examples/agent-recv.yaml`. A literal secret typed in an `export` command may persist in shell history. Passing `-k "$KREAMLINK_CHANNEL"` expands the secret into the process arguments, which other tenants may be able to read. Child processes also inherit exported variables, so set them in the shell or service that launches the intended role.

## Separate credential files

Create the files as the account that runs kreamlink. This Bash example provisions **new** random secrets, keeps their values out of command arguments, and refuses to overwrite existing files. Run it once, then provision the same values on the machines that need them through your secret manager. The Hub only needs the registration password.

```bash
(
    set -eC
    umask 077
    dir="$HOME/.config/kreamlink"
    mkdir -p "$dir"
    chmod 700 "$dir"
    openssl rand -hex 32 > "$dir/hub.password"
    openssl rand -hex 32 > "$dir/channel.secret"
)
```

Reference the files by path in your YAML. Use your actual home directory. Relative paths resolve from the process working directory.

```yaml
hub_password_file: "/home/tenant/.config/kreamlink/hub.password"
# Include only on the Receiver and Sender.
channel_file: "/home/tenant/.config/kreamlink/channel.secret"
```

Each file must be a regular file owned by the process's effective UID with mode `0600` or `0400`. For an existing private file, use `chmod 600` on that file as its owner. Keep the containing directory private and remove any ACLs that grant access to other tenants. The loader rejects a symlink at the secret filename. The file contains one value of 1 to 255 bytes, with an optional final LF or CRLF. It is read at startup.

An environment variable takes precedence over its file. An explicitly empty variable fails startup. Unset it to use the file. Replace any inline `hub_password` setting with `hub_password_file`. For older agent configurations, migrate the inline `channel` value or the `-k` argument to `KREAMLINK_CHANNEL` or `channel_file`. If the old secret was exposed in a process listing, shell history, or shared configuration, rotate it on the affected roles.
