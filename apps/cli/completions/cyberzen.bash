# Source this file to enable CyberZen bash completion.
_cyberzen_complete() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W "auth agents billing dashboard tenants link unlink findings repos scan scans sbom drift gates attack trust threat compliance reports sla remediation security crypto repository traffic webhooks siem honeypot sandbox marketplace mssp memory integrations jobs status system" -- "$cur") )
}
complete -F _cyberzen_complete cyberzen
