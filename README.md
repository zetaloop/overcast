# Overcast
  
  Manage proxy users and routing from the terminal. Overcast generates configurations and runs Xray, sing-box, and Mihomo for you.
  
  Download the executable for your platform from [Releases](https://github.com/zetaloop/overcast/releases).
  
  ## Usage
  
  Run `overcast` to open the interface. Command-line arguments act as menu shortcuts: `overcast add-user Alice` opens a new user profile with the name Alice.
  
  Turn on **Run service** under **Maintenance** to start at boot and apply configuration changes as you save them. Registering the service requires administrator privileges.
  
  Overcast stores its data in `/var/lib/overcast` on Linux, `/Library/Application Support/Overcast` on macOS, and `%ProgramData%\Overcast` on Windows. Set `OVERCAST_HOME` to use another directory.
  
  ## Build
  
  `cargo build --release`
  