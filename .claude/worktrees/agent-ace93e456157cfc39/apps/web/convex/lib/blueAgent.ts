/**
 * Blue Agent — Detection Rule Generator (spec §3.3.3)
 *
 * Takes exploit chains and vulnerability signals from Red Agent wins and
 * generates detection rules exportable to production security tooling.
 *
 * Output formats:
 *   - nginx / ModSecurity WAF rules
 *   - Splunk SPL queries
 *   - Elastic (Kibana) KQL queries
 *   - Microsoft Sentinel (Azure Monitor) KQL queries
 *   - Generic log regex patterns (for Datadog, Loki, CloudWatch Logs Insights)
 *
 * Design: Pure functions — no DB access. All inputs come from redBlueRounds.
 */

// ── Input / output types ──────────────────────────────────────────────────────

export type RedAgentRoundInput = {
  exploitChains: string[]         // e.g. ["sqli_union/payments-db", "path_traversal/etc/passwd"]
  redStrategySummary: string
  attackSurfaceCoverage: number   // 0–100
  blueDetectionScore: number      // 0–100
  roundOutcome: 'red_wins' | 'blue_wins' | 'draw'
  repositoryName: string
}

export type DetectionRule = {
  ruleId: string
  name: string
  description: string
  format: DetectionRuleFormat
  severity: 'critical' | 'high' | 'medium' | 'low'
  content: string
  exploitChainSource: string
  tags: string[]
}

export type DetectionRuleFormat =
  | 'nginx_deny'
  | 'modsecurity'
  | 'splunk_spl'
  | 'elastic_kql'
  | 'sentinel_kql'
  | 'log_regex'

export type DetectionRuleSet = {
  repositoryName: string
  generatedAt: number
  totalRules: number
  nginx: DetectionRule[]
  modsecurity: DetectionRule[]
  splunk: DetectionRule[]
  elastic: DetectionRule[]
  sentinel: DetectionRule[]
  logRegex: DetectionRule[]
  summary: string
}

// ── Vulnerability class → detection patterns ──────────────────────────────────

type RuleTemplate = {
  vuln_class: string
  nginx_patterns: string[]          // URI/query string patterns to deny
  request_body_patterns: string[]   // POST body patterns
  log_patterns: string[]            // regex for log analysis
  splunk_filter: string             // SPL filter condition
  elastic_filter: string            // KQL filter
  severity: DetectionRule['severity']
}

const RULE_TEMPLATES: RuleTemplate[] = [
  {
    vuln_class: 'sql_injection',
    nginx_patterns: [
      "~* \"(?:'|%27)[[:space:]]*(or|and|union|select|insert|delete|update|drop)[[:space:]]\"",
      "~* \"union[[:space:]]+select\"",
      "~* \"(sleep|benchmark|waitfor)[[:space:]]*[(]\"",
    ],
    request_body_patterns: [
      "~* \"(?:'|%27)[[:space:]]*(or|and)[[:space:]]+[0-9]+[[:space:]]*=[[:space:]]*[0-9]\"",
    ],
    log_patterns: [
      "(?:'|%27)\\s*(?:or|and|union|select|drop|insert|delete|update)\\s",
      "(?:sleep|benchmark|waitfor)\\s*[(]",
    ],
    splunk_filter: 'url_query="*union*select*" OR uri_path="*sleep(*" OR url_query="*%27*"',
    elastic_filter: 'url.query: (*union*select* OR *%27*) OR url.original: *sleep(*',
    severity: 'critical',
  },
  {
    vuln_class: 'xss',
    nginx_patterns: [
      '~* "<script[^>]*>"',
      '~* "javascript:"',
      '~* "onerror[[:space:]]*=|onload[[:space:]]*="',
    ],
    request_body_patterns: [
      '~* "<[[:space:]]*(script|iframe|object|embed|svg)[^>]*>"',
    ],
    log_patterns: [
      '<script[^>]*>',
      'javascript:',
      'on(?:error|load|click|mouse)\\s*=',
    ],
    splunk_filter: 'url_query="*<script*" OR url_query="*javascript:*" OR request_body="*onerror=*"',
    elastic_filter: 'url.query: (*<script* OR *javascript:*) OR http.request.body.content: *onerror=*',
    severity: 'high',
  },
  {
    vuln_class: 'path_traversal',
    nginx_patterns: [
      '~* "([.][.]/|%2e%2e%2f|%252e%252e%252f)"',
      '~* "etc/passwd|etc/shadow|proc/self/environ"',
    ],
    request_body_patterns: [],
    log_patterns: [
      '\\.\\./|\\.\\.\\\\/|\\.\\.',
      '%2e%2e%2f|%252e%252e',
      '(?:/etc/passwd|/etc/shadow|/proc/self)',
    ],
    splunk_filter: 'uri_path="*../*" OR uri_path="*%2e%2e%2f*" OR uri_path="*/etc/passwd*"',
    elastic_filter: 'url.path: (*../* OR *%2e%2e%2f* OR */etc/passwd*)',
    severity: 'high',
  },
  {
    vuln_class: 'command_injection',
    nginx_patterns: [
      '~* ";[[:space:]]*(id|whoami|ls|cat|wget|curl|bash|sh)[[:space:]]"',
      '~* "[|][[:space:]]*(id|whoami|cat|nc|bash)"',
      '~* "[$][(][[:space:]]*(id|whoami|cat)"',
    ],
    request_body_patterns: [
      '~* "`[[:space:]]*(id|whoami|ls|cat)[[:space:]]*`"',
    ],
    log_patterns: [
      ';\\s*(?:id|whoami|ls|cat|wget|curl|bash|sh)\\s',
      '[|]\\s*(?:id|whoami|cat|nc|bash)',
      '[$][(](?:id|whoami|cat)',
    ],
    splunk_filter: 'url_query="*; id*" OR url_query="*| whoami*" OR request_body="*$(id)*"',
    elastic_filter: 'url.query: (*; id* OR *| whoami*) OR http.request.body.content: *$(id)*',
    severity: 'critical',
  },
  {
    vuln_class: 'ssrf',
    nginx_patterns: [
      '~* "169[.]254[.]169[.]254|metadata[.]google[.]internal"',
      '~* "(?:file|dict|gopher|ldap)://"',
    ],
    request_body_patterns: [
      '~* "(?:http|https)://(?:localhost|127[.]|10[.]|192[.]168[.])"',
    ],
    log_patterns: [
      '169[.]254[.]169[.]254|metadata[.]google[.]internal',
      '(?:file|dict|gopher|ldap)://',
      '(?:http|https)://(?:localhost|127[.][0-9]|10[.]|192[.]168[.])',
    ],
    splunk_filter: 'request_body="*169.254.169.254*" OR request_body="*file://*" OR request_body="*gopher://*"',
    elastic_filter: 'http.request.body.content: (*169.254.169.254* OR *file://* OR *gopher://*)',
    severity: 'critical',
  },
  {
    vuln_class: 'auth_bypass',
    nginx_patterns: [],
    request_body_patterns: [],
    log_patterns: [
      'HTTP/[0-9][.][0-9]" 200 .* /admin',
      'Authorization: Basic [A-Za-z0-9+/]{0,8}=*',
    ],
    splunk_filter: 'status=200 uri_path="/admin*" user="unknown"',
    elastic_filter: 'http.response.status_code: 200 AND url.path: /admin* AND user.name: unknown',
    severity: 'critical',
  },
  {
    vuln_class: 'jwt_validation_bypass',
    nginx_patterns: [],
    request_body_patterns: [],
    log_patterns: [
      'eyJhbGciOiJub25lIi',
    ],
    splunk_filter: 'http_header_authorization="*eyJhbGciOiJub25lIi*"',
    elastic_filter: 'http.request.headers.authorization: *eyJhbGciOiJub25lIi*',
    severity: 'critical',
  },
  {
    vuln_class: 'local_file_inclusion',
    nginx_patterns: [
      '~* "(?:include|require).*[.][.]/"',
      '~* "php://(?:input|filter|fd)"',
    ],
    request_body_patterns: [],
    log_patterns: [
      '(?:include|require).*\\.\\./',
      'php://(?:input|filter|fd)',
    ],
    splunk_filter: 'url_query="*php://input*" OR url_query="*php://filter*"',
    elastic_filter: 'url.query: (*php://input* OR *php://filter*)',
    severity: 'high',
  },
]

// ── Rule generation ───────────────────────────────────────────────────────────

function detectVulnClass(chain: string): string | null {
  const lower = chain.toLowerCase()
  for (const t of RULE_TEMPLATES) {
    if (lower.includes(t.vuln_class.replace(/_/g, '_')) ||
        lower.includes(t.vuln_class.replace(/_/g, '')) ||
        lower.includes(t.vuln_class.split('_')[0])) {
      return t.vuln_class
    }
  }
  // Fuzzy fallbacks
  if (/sql|sqli/.test(lower)) return 'sql_injection'
  if (/xss|cross.site/.test(lower)) return 'xss'
  if (/path|traversal|lfi|directory/.test(lower)) return 'path_traversal'
  if (/cmd|command|shell|rce|exec/.test(lower)) return 'command_injection'
  if (/ssrf|request.forgery/.test(lower)) return 'ssrf'
  if (/auth|bypass|jwt|token/.test(lower)) return 'auth_bypass'
  return null
}

function buildNginxRules(
  template: RuleTemplate,
  chain: string,
  ruleIdBase: string,
): DetectionRule[] {
  const rules: DetectionRule[] = []

  template.nginx_patterns.forEach((pattern, i) => {
    rules.push({
      ruleId: `${ruleIdBase}-nginx-${i + 1}`,
      name: `Sentinel: Block ${template.vuln_class.replace(/_/g, ' ')} attempt`,
      description: `nginx deny rule for ${template.vuln_class} attack pattern from exploit chain: ${chain}`,
      format: 'nginx_deny',
      severity: template.severity,
      content: [
        `# Sentinel Detection Rule — ${template.vuln_class} (from Red Agent)`,
        `# Source exploit chain: ${chain}`,
        `location ~ / {`,
        `    if ($request_uri ${pattern}) {`,
        `        return 403;`,
        `    }`,
        `}`,
      ].join('\n'),
      exploitChainSource: chain,
      tags: ['sentinel-auto', 'waf', template.vuln_class, 'nginx'],
    })
  })

  return rules
}

function buildModSecurityRules(
  template: RuleTemplate,
  chain: string,
  ruleIdBase: string,
): DetectionRule[] {
  const rules: DetectionRule[] = []
  const severityMap = { critical: '2', high: '3', medium: '4', low: '5' }

  template.nginx_patterns.concat(template.request_body_patterns).forEach((pattern, i) => {
    const ruleNum = 9900000 + parseInt(ruleIdBase.replace(/\D/g, '').slice(0, 4) || '0') + i
    rules.push({
      ruleId: `${ruleIdBase}-modsec-${i + 1}`,
      name: `SENTINEL-${ruleNum}: ${template.vuln_class.toUpperCase()}`,
      description: `ModSecurity rule for ${template.vuln_class} from exploit chain: ${chain}`,
      format: 'modsecurity',
      severity: template.severity,
      content: [
        `# Sentinel Detection Rule — ${template.vuln_class}`,
        `# Source: Red Agent exploit chain: ${chain}`,
        `SecRule REQUEST_URI|ARGS|REQUEST_BODY "${pattern}"`,
        `    "id:${ruleNum},`,
        `     phase:2,`,
        `     deny,`,
        `     status:403,`,
        `     severity:${severityMap[template.severity]},`,
        `     msg:'Sentinel: ${template.vuln_class.replace(/_/g, ' ')} attempt detected',`,
        `     logdata:'%{MATCHED_VAR}',`,
        `     tag:'sentinel-auto',`,
        `     tag:'${template.vuln_class}'"`,
      ].join('\n'),
      exploitChainSource: chain,
      tags: ['sentinel-auto', 'modsecurity', 'waf', template.vuln_class],
    })
  })

  return rules
}

function buildSplunkQuery(
  template: RuleTemplate,
  chain: string,
  ruleIdBase: string,
): DetectionRule {
  return {
    ruleId: `${ruleIdBase}-splunk`,
    name: `Sentinel: Detect ${template.vuln_class.replace(/_/g, ' ')} in web logs`,
    description: `Splunk SPL alert for ${template.vuln_class} detected by Red Agent exploit chain: ${chain}`,
    format: 'splunk_spl',
    severity: template.severity,
    content: [
      `| Sentinel Detection Query — ${template.vuln_class}`,
      `| Source exploit chain: ${chain}`,
      `index=web_access OR index=nginx_access`,
      `${template.splunk_filter}`,
      `| stats count by src_ip, uri_path, status`,
      `| where count > 5`,
      `| eval alert_name="SENTINEL: ${template.vuln_class.toUpperCase()} attempt from " + src_ip`,
      `| table _time, src_ip, uri_path, status, count, alert_name`,
    ].join('\n'),
    exploitChainSource: chain,
    tags: ['sentinel-auto', 'splunk', 'siem', template.vuln_class],
  }
}

function buildElasticQuery(
  template: RuleTemplate,
  chain: string,
  ruleIdBase: string,
): DetectionRule {
  return {
    ruleId: `${ruleIdBase}-elastic`,
    name: `Sentinel: ${template.vuln_class.replace(/_/g, ' ')} detection`,
    description: `Elastic KQL rule for ${template.vuln_class}. Source: ${chain}`,
    format: 'elastic_kql',
    severity: template.severity,
    content: [
      `// Sentinel Detection Rule — ${template.vuln_class}`,
      `// Source exploit chain: ${chain}`,
      `// Paste into Kibana → Stack Management → Detection Rules → Create Rule → Custom Query`,
      ``,
      `event.dataset: "nginx.access" AND (${template.elastic_filter})`,
      ``,
      `// Recommended: alert when count > 10 over last 5 minutes from same source IP`,
    ].join('\n'),
    exploitChainSource: chain,
    tags: ['sentinel-auto', 'elastic', 'siem', template.vuln_class],
  }
}

function buildSentinelKqlQuery(
  template: RuleTemplate,
  chain: string,
  ruleIdBase: string,
): DetectionRule {
  // Convert Elastic KQL to Sentinel KQL (similar syntax with table differences)
  const sentinelFilter = template.elastic_filter
    .replace('url.query:', 'url_query')
    .replace('url.path:', 'uriPath')
    .replace('http.request.body.content:', 'requestBody')
    .replace('http.response.status_code:', 'statusCode')
    .replace('url.original:', 'requestURL')
    .replace('user.name:', 'accountName')

  return {
    ruleId: `${ruleIdBase}-sentinel`,
    name: `Sentinel: ${template.vuln_class.replace(/_/g, ' ')} detection (Azure Sentinel)`,
    description: `Microsoft Sentinel KQL rule for ${template.vuln_class}. Source: ${chain}`,
    format: 'sentinel_kql',
    severity: template.severity,
    content: [
      `// Sentinel Detection Rule — ${template.vuln_class}`,
      `// Source exploit chain: ${chain}`,
      `// Paste into Microsoft Sentinel → Analytics → Create scheduled query rule`,
      ``,
      `AzureDiagnostics`,
      `| where Category == "ApplicationGatewayAccessLog"`,
      `| where ${sentinelFilter}`,
      `| summarize Count = count() by requestUri_s, clientIP_s, bin(TimeGenerated, 5m)`,
      `| where Count > 5`,
      `| project TimeGenerated, clientIP_s, requestUri_s, Count`,
      `| extend AlertSeverity = "${template.severity.toUpperCase()}", AlertName = "SENTINEL: ${template.vuln_class.toUpperCase()}"`,
    ].join('\n'),
    exploitChainSource: chain,
    tags: ['sentinel-auto', 'azure-sentinel', 'siem', template.vuln_class],
  }
}

function buildLogRegexPatterns(
  template: RuleTemplate,
  chain: string,
  ruleIdBase: string,
): DetectionRule[] {
  return template.log_patterns.map((pattern, i) => ({
    ruleId: `${ruleIdBase}-regex-${i + 1}`,
    name: `Sentinel: ${template.vuln_class.replace(/_/g, ' ')} log pattern`,
    description: `Regex pattern for detecting ${template.vuln_class} in application logs. Source: ${chain}`,
    format: 'log_regex' as const,
    severity: template.severity,
    content: [
      `# Sentinel Detection Pattern — ${template.vuln_class}`,
      `# Source exploit chain: ${chain}`,
      `# Compatible with: Datadog Log Management, AWS CloudWatch Logs Insights, Grafana Loki`,
      ``,
      `PATTERN: ${pattern}`,
      ``,
      `# CloudWatch Logs Insights:`,
      `# filter @message like /${pattern}/`,
      ``,
      `# Grafana Loki:`,
      `# {job="nginx"} |~ "${pattern}"`,
    ].join('\n'),
    exploitChainSource: chain,
    tags: ['sentinel-auto', 'log-regex', template.vuln_class],
  }))
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Generate a complete detection rule set from Red Agent rounds.
 * Call this when roundOutcome === 'red_wins' to create exportable rules.
 */
export function generateDetectionRules(
  rounds: RedAgentRoundInput[],
  repositoryName: string,
): DetectionRuleSet {
  const nginx: DetectionRule[] = []
  const modsecurity: DetectionRule[] = []
  const splunk: DetectionRule[] = []
  const elastic: DetectionRule[] = []
  const sentinel: DetectionRule[] = []
  const logRegex: DetectionRule[] = []

  const seenVulnClasses = new Set<string>()

  for (const round of rounds) {
    if (round.roundOutcome !== 'red_wins') continue

    for (const chain of round.exploitChains) {
      const vulnClass = detectVulnClass(chain)
      if (!vulnClass || seenVulnClasses.has(vulnClass)) continue
      seenVulnClasses.add(vulnClass)

      const template = RULE_TEMPLATES.find((t) => t.vuln_class === vulnClass)
      if (!template) continue

      const baseId = `${repositoryName.replace(/[^a-z0-9]/gi, '-').slice(0, 20)}-${vulnClass.replace(/_/g, '-')}`

      nginx.push(...buildNginxRules(template, chain, baseId))
      modsecurity.push(...buildModSecurityRules(template, chain, baseId))
      splunk.push(buildSplunkQuery(template, chain, baseId))
      elastic.push(buildElasticQuery(template, chain, baseId))
      sentinel.push(buildSentinelKqlQuery(template, chain, baseId))
      logRegex.push(...buildLogRegexPatterns(template, chain, baseId))
    }
  }

  const total = nginx.length + modsecurity.length + splunk.length +
    elastic.length + sentinel.length + logRegex.length

  const classNames = [...seenVulnClasses].map((c) => c.replace(/_/g, ' ')).join(', ')

  return {
    repositoryName,
    generatedAt: Date.now(),
    totalRules: total,
    nginx,
    modsecurity,
    splunk,
    elastic,
    sentinel,
    logRegex,
    summary: total > 0
      ? `Generated ${total} detection rules across ${seenVulnClasses.size} vulnerability class${seenVulnClasses.size === 1 ? '' : 'es'}: ${classNames}. Rules are ready for export to your WAF, SIEM, and log monitoring stack.`
      : `No Red Agent wins recorded yet — detection rules will be generated after the first confirmed exploit.`,
  }
}

/**
 * Merge two rule sets (e.g. across multiple scan sessions).
 * Deduplicates by ruleId.
 */
export function mergeRuleSets(a: DetectionRuleSet, b: DetectionRuleSet): DetectionRuleSet {
  function merge<T extends { ruleId: string }>(arrA: T[], arrB: T[]): T[] {
    const seen = new Set(arrA.map((r) => r.ruleId))
    return [...arrA, ...arrB.filter((r) => !seen.has(r.ruleId))]
  }

  const merged: DetectionRuleSet = {
    repositoryName: a.repositoryName,
    generatedAt: Date.now(),
    nginx: merge(a.nginx, b.nginx),
    modsecurity: merge(a.modsecurity, b.modsecurity),
    splunk: merge(a.splunk, b.splunk),
    elastic: merge(a.elastic, b.elastic),
    sentinel: merge(a.sentinel, b.sentinel),
    logRegex: merge(a.logRegex, b.logRegex),
    totalRules: 0,
    summary: '',
  }

  merged.totalRules = merged.nginx.length + merged.modsecurity.length +
    merged.splunk.length + merged.elastic.length +
    merged.sentinel.length + merged.logRegex.length

  merged.summary = `${merged.totalRules} detection rules across all formats.`
  return merged
}
