# sudo.conf with frisket-sudo's plugin line, built only when
# frisket-sudo-check-plugin loads the plugin as sudo would and finds an audit
# plugin of this sudo's API major built for this sudo version (guard 1).
{ pkgs, plugin }:
{ so ? "${plugin}/lib/frisket_sudo.so", symbol ? "frisket_audit", version, user }:
let inherit (pkgs.lib) escapeShellArg; in
pkgs.runCommand "sudo.conf" { } ''
  ${plugin}/bin/frisket-sudo-check-plugin ${escapeShellArg so} ${escapeShellArg symbol} ${escapeShellArg version}
  echo ${escapeShellArg "Plugin ${symbol} ${so} user=${user}"} > $out
''
