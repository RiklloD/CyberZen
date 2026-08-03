const COMMANDS = [
	"auth",
	"agents",
	"billing",
	"dashboard",
	"tenants",
	"link",
	"unlink",
	"findings",
	"repos",
	"scan",
	"scans",
	"sbom",
	"drift",
	"gates",
	"attack",
	"trust",
	"threat",
	"compliance",
	"reports",
	"sla",
	"remediation",
	"security",
	"crypto",
	"repository",
	"traffic",
	"webhooks",
	"siem",
	"honeypot",
	"sandbox",
	"marketplace",
	"mssp",
	"memory",
	"integrations",
	"jobs",
	"status",
	"system",
] as const;

const COMMAND_WORDS = COMMANDS.join(" ");
const dollar = "$";

export function completionScript(shell: string): string {
	switch (shell) {
		case "bash":
			return `# CyberZen bash completion
_cyberzen_complete() {
  local cur="${dollar}{COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=( $(compgen -W "${COMMAND_WORDS}" -- "$cur") )
}
complete -F _cyberzen_complete cyberzen
`;
		case "zsh":
			return `# CyberZen zsh completion
#compdef cyberzen
_arguments '1:command:(${COMMAND_WORDS})'
`;
		case "fish":
			return `${COMMANDS.map((command) => `complete -c cyberzen -n '__fish_use_subcommand' -a '${command}'`).join("\n")}\n`;
		default:
			throw new Error(`Unsupported shell: ${shell}. Use bash, zsh, or fish.`);
	}
}
