# Overcast

Overcast is a terminal-based proxy orchestrator for Xray, sing-box, and Mihomo. A single routing tree determines where traffic goes based on the inbound, the user, and the destination. For example, guests can connect directly while other users go through an upstream proxy. Overcast translates those rules into native configurations and runs the services they require.

## Getting started

Install Overcast with Scoop, Homebrew, or Nix via [zetaloop/zetaloop](https://github.com/zetaloop/zetaloop), or download the standalone executable from [Releases](https://github.com/zetaloop/overcast/releases). The standalone version can update itself through **Settings → Updates → Scheduled updates**.

Configure your inbounds, outbounds, and routing rules, then turn on **Run service** under **Settings**. This requires administrator privileges. The service starts at boot and applies changes as you save them.

You can also pass menu actions on the command line. For example, `overcast add-user Alice` opens the user editor with the name already filled in.

## Data directory

| Platform | Default location |
| --- | --- |
| Linux | `/var/lib/overcast` |
| macOS | `/Library/Application Support/Overcast` |
| Windows | `%ProgramData%\Overcast` |

## Build from source

```sh
cargo build --release
```
