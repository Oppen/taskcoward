# TaskCoward: the TaskWarrior sync server that would rather hide

TaskCoward tries to be the smallest, least resource hungry sync server for the TaskChampion protocol, while retaining full compatibility with existing clients.

# Installation

You'll need an HTTP server with support for CGI. My recommendation is `tipidee`.
Run `zig build`, then copy the binaries to the desired root directory for your deployment of TaskCoward, preferably under the `bin` subdirectory.
Then, make sure the programs have access to the path to TaskCoward's root by setting the `TC_ROOT_DIR` enviroment variable, and that the `SCRIPT_NAME` variable for each program matches the pattern `/v1/client/<program>`.
In `tipidee`, I do that by creating a directory `v1/client/` inside the domain's document root with scripts following the template:
```sh
#!/usr/bin/execlineb -P

define TC_ROOT_DIR <path> # Define the path locally for the script
export TC_ROOT_DIR ${TC_ROOT_DIR} # Export it as enviroment variable for CGI programs to use
${TC_ROOT_DIR}/bin/<program> # Execute the appropriate program
```
In the template, you are expected to replace `<path>` and `<program>` with your deployment's root and each program name, and the script to be named after the program it executes into.

# Acknowledgements

This code is based on documents by the TaskChampion team, their own server, and TaskWarrior.
Some inspiration was drawn from Skarnet's `execline` and its chainloading approach. TaskCoward's first iteration was going to be a set of `execline` scripts, but due to the custom database I would have ended up writing almost as much Zig code for it as I did for the program itself, so I ended up ditching that version.
