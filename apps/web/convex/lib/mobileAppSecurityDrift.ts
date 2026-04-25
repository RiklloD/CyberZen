// WS-74 — Mobile Application Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to mobile application security configuration files. This scanner focuses on
// the *mobile client security layer* — configurations that control what a mobile
// app is permitted to do (iOS entitlements), how Android components are exposed
// (AndroidManifest.xml), how the app is signed and distributed (signing keystores
// and provisioning profiles), and how the runtime security surface is configured
// (ProGuard/R8 obfuscation rules, Firebase service config, deep link verification).
//
// DISTINCT from:
//   WS-60  securityConfigDrift    — server-side TLS/CORS/JWT/session configs in
//                                   backend applications, not mobile client security
//   WS-66  certPkiDrift           — covers cert pinning (TrustKit, NSC, HPKP) and
//                                   SSH key material; WS-74 covers the broader mobile
//                                   security surface beyond cert pinning alone
//   WS-68  networkFirewallDrift   — server-side network perimeter (iptables, UFW,
//                                   HAProxy, VPN configs), not mobile app configs
//   WS-70  identityAccessDrift    — server-side IAM (LDAP, Vault, sudo/PAM, SAML);
//                                   WS-74 covers mobile-specific signing and entitlement
//                                   configurations
//
// Covered rule groups (8 rules):
//
//   IOS_ENTITLEMENTS_DRIFT           — iOS/macOS/watchOS app entitlement files
//   ANDROID_MANIFEST_DRIFT           — AndroidManifest.xml ← user contribution
//   MOBILE_SIGNING_CONFIG_DRIFT      — iOS provisioning profiles and Android keystores
//   IOS_APP_SECURITY_CONFIG_DRIFT    — Info.plist ATS/privacy, PrivacyInfo.xcprivacy
//   ANDROID_OBFUSCATION_CONFIG_DRIFT — ProGuard/R8 obfuscation rules
//   MOBILE_FIREBASE_CONFIG_DRIFT     — Firebase/Google services config files
//   MOBILE_DEEP_LINK_CONFIG_DRIFT    — Universal Links and Android App Links configs
//   MOBILE_PLATFORM_CONFIG_DRIFT     — EAS, Capacitor, Podfile.lock, xcconfig
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–73 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • .entitlements extension is globally unambiguous for Apple platform apps.
//   • AndroidManifest.xml disambiguation is the user contribution — see
//     isAndroidManifestSecurityFile.
//   • google-services.json and GoogleService-Info.plist are globally unambiguous
//     Firebase config filenames with no plausible non-Firebase usage.
//
// Exports:
//   isAndroidManifestSecurityFile    — user contribution point (see JSDoc below)
//   MOBILE_APP_SECURITY_RULES        — readonly rule registry
//   scanMobileAppSecurityDrift       — main scanner, returns MobileAppSecurityDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type MobileAppSecurityRuleId =
  | 'IOS_ENTITLEMENTS_DRIFT'
  | 'ANDROID_MANIFEST_DRIFT'
  | 'MOBILE_SIGNING_CONFIG_DRIFT'
  | 'IOS_APP_SECURITY_CONFIG_DRIFT'
  | 'ANDROID_OBFUSCATION_CONFIG_DRIFT'
  | 'MOBILE_FIREBASE_CONFIG_DRIFT'
  | 'MOBILE_DEEP_LINK_CONFIG_DRIFT'
  | 'MOBILE_PLATFORM_CONFIG_DRIFT'

export type MobileAppSecuritySeverity = 'high' | 'medium' | 'low'
export type MobileAppSecurityRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type MobileAppSecurityDriftFinding = {
  ruleId: MobileAppSecurityRuleId
  severity: MobileAppSecuritySeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type MobileAppSecurityDriftResult = {
  riskScore: number
  riskLevel: MobileAppSecurityRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: MobileAppSecurityDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VENDOR_DIRS = [
  'node_modules/', '.git/', 'dist/', 'build/', '.next/', '.nuxt/',
  'vendor/', 'bower_components/', 'coverage/', '__pycache__/',
  '.terraform/', 'cdk.out/', '.cdk/', '.gradle/', '.m2/',
  'target/', 'out/', '.idea/', '.vscode/', '.cache/',
]

const HIGH_PENALTY_PER = 15
const HIGH_PENALTY_CAP = 45
const MED_PENALTY_PER  = 8
const MED_PENALTY_CAP  = 25
const LOW_PENALTY_PER  = 4
const LOW_PENALTY_CAP  = 15

// iOS/Apple platform directory segments that make Info.plist and .xcconfig
// context unambiguous (these dirs appear only in Apple platform projects).
const IOS_DIRS = [
  'ios/', 'macos/', 'osx/', 'watchos/', 'tvos/', 'visionos/',
  'xcodeproj/', 'xcworkspace/', 'runner/',
]

// ---------------------------------------------------------------------------
// Detection helpers — IOS_ENTITLEMENTS_DRIFT
// ---------------------------------------------------------------------------

function isIosEntitlementsFile(_pathLower: string, base: string): boolean {
  // .entitlements — Xcode entitlement files defining app capabilities (keychain
  // access groups, HealthKit, iCloud containers, push notifications, NFC, Apple
  // Pay). Used exclusively by Apple platform apps — globally unambiguous.
  if (base.endsWith('.entitlements')) return true
  // ExportOptions.plist — specifies the code signing identity, provisioning
  // profile, and distribution method when exporting an Xcode archive.
  if (base === 'exportoptions.plist') return true
  return false
}

// ---------------------------------------------------------------------------
// ANDROID_MANIFEST_DRIFT — user contribution point
// ---------------------------------------------------------------------------

/**
 * isAndroidManifestSecurityFile — determines whether a changed AndroidManifest.xml
 * is a security-relevant production manifest rather than a test-only manifest.
 *
 * Context: Android projects contain multiple AndroidManifest.xml files:
 *   (a) src/main/AndroidManifest.xml — the primary app manifest. This is merged
 *       into the final APK/AAB and defines the app's declared permissions, exported
 *       Activity/Service/BroadcastReceiver/ContentProvider components, backup rules,
 *       network security config reference, debuggable flag, and target SDK version.
 *       Changes here are always security-relevant.
 *
 *   (b) src/androidTest/AndroidManifest.xml — used only during instrumented tests
 *       on real devices; NOT included in production builds. False-positive risk if
 *       flagged, since test manifests often grant broader permissions for the test
 *       harness.
 *
 *   (c) src/debug/AndroidManifest.xml — the debug build-type manifest overlay.
 *       Can set android:debuggable="true" or add debug-only components. Changes
 *       here may indicate experimentation with weakened security that could later
 *       migrate to the main manifest.
 *
 *   (d) src/test/AndroidManifest.xml — JVM unit test manifest; NOT in production
 *       builds. High false-positive risk.
 *
 *   (e) src/free/AndroidManifest.xml (flavour manifests) — merged into the final
 *       build. Security-relevant and should be flagged.
 *
 * Design trade-offs:
 *   • Excluding only androidTest/ and test/ → best signal-to-noise ratio: production,
 *     debug, and flavour manifests are flagged; test-harness manifests are not.
 *   • Excluding debug/ as well → less noise, but misses debug manifests that weaken
 *     security (e.g., cleartext traffic permissions) before migrating to main.
 *   • Flagging ALL manifests → maximum recall but noisy in test-heavy projects.
 *
 * Implement to return true for AndroidManifest.xml files that are part of the
 * production or debug build (security-relevant) and false for manifests that live
 * exclusively in test source sets.
 */
export function isAndroidManifestSecurityFile(pathLower: string): boolean {
  const base = pathLower.split('/').at(-1) ?? pathLower
  if (base !== 'androidmanifest.xml') return false

  // Exclude test source sets — these are never included in production builds
  const TEST_DIRS = [
    'androidtest/',
    '/test/',
    'testdebug/',
    'testrelease/',
    'unittests/',
    'integrationtest/',
    'uitest/',
  ]
  for (const dir of TEST_DIRS) {
    if (pathLower.includes(dir)) return false
  }

  return true
}

// ---------------------------------------------------------------------------
// Detection helpers — MOBILE_SIGNING_CONFIG_DRIFT
// ---------------------------------------------------------------------------

function isMobileSigningConfig(pathLower: string, base: string): boolean {
  // .mobileprovision — Apple provisioning profiles: define which entitlements an
  // app is permitted, which team ID signs it, which bundle IDs it covers, and
  // (for development) which device UDIDs are authorized.
  if (base.endsWith('.mobileprovision')) return true

  // .jks / .keystore — Java KeyStore files containing Android signing key pairs.
  // These should never be committed to source control.
  if (base.endsWith('.jks') || base.endsWith('.keystore')) return true

  // signing.properties / keystore.properties — store keystore path, alias, and
  // passwords in plaintext — plaintext credential risk.
  if (base === 'signing.properties' || base === 'keystore.properties') return true

  // key.properties — Flutter Android signing config (stores keyAlias, keyPassword,
  // storeFile, storePassword). Gated on android/ dir to avoid false positives.
  if (base === 'key.properties' && pathLower.includes('android/')) return true

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — IOS_APP_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

function isIosAppSecurityConfig(pathLower: string, base: string): boolean {
  // PrivacyInfo.xcprivacy — Apple Privacy Manifest (required for SDK authors
  // distributing via XCFramework/SPM since Spring 2024). Declares privacy-sensitive
  // API access reasons. The .xcprivacy extension is exclusively Apple.
  if (base === 'privacyinfo.xcprivacy') return true

  // ATS.plist — explicit App Transport Security settings file (enterprise configs).
  if (base === 'ats.plist') return true

  // Info.plist — primary iOS/macOS/watchOS app property list. Contains ATS exception
  // domains (NSAppTransportSecurity), privacy usage strings, URL scheme registrations
  // (CFBundleURLTypes), and universal link entitlement references.
  // Gated on iOS/Apple platform dirs to avoid false positives with Info.plist files
  // in Java/other contexts.
  if (base === 'info.plist') {
    for (const dir of IOS_DIRS) {
      if (pathLower.includes(dir)) return true
    }
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — ANDROID_OBFUSCATION_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const PROGUARD_UNGATED = new Set([
  'proguard-rules.pro',
  'consumer-rules.pro',
  'proguard-android.txt',
  'proguard-android-optimize.txt',
  'r8-rules.txt',
])

function isAndroidObfuscationConfig(pathLower: string, base: string): boolean {
  if (PROGUARD_UNGATED.has(base)) return true

  if (pathLower.includes('proguard/') &&
      (base.endsWith('.pro') || base.endsWith('.txt') || base.endsWith('.cfg'))) {
    return true
  }

  if (base.startsWith('proguard-') &&
      (base.endsWith('.pro') || base.endsWith('.txt') || base.endsWith('.cfg'))) {
    return true
  }

  if (base.startsWith('r8-') && (base.endsWith('.txt') || base.endsWith('.pro'))) {
    return true
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — MOBILE_FIREBASE_CONFIG_DRIFT
// ---------------------------------------------------------------------------

const FIREBASE_UNGATED = new Set([
  'google-services.json',
  'googleservice-info.plist',
  '.firebaserc',
  'firebase-config.json',
  'firebaseconfig.json',
  'firebase.json',
])

function isMobileFirebaseConfig(pathLower: string, base: string): boolean {
  if (FIREBASE_UNGATED.has(base)) return true

  // Any JSON/YAML inside a firebase/ directory
  if (pathLower.includes('firebase/') &&
      (base.endsWith('.json') || base.endsWith('.yaml') || base.endsWith('.yml'))) {
    return true
  }

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — MOBILE_DEEP_LINK_CONFIG_DRIFT
// ---------------------------------------------------------------------------

function isMobileDeepLinkConfig(pathLower: string, base: string): boolean {
  // apple-app-site-association — iOS Universal Links site association file.
  // No extension; defines URL paths that open in the app instead of Safari.
  // Globally unambiguous — this specific name is exclusively used for this purpose.
  if (base === 'apple-app-site-association') return true

  // digital-asset-links.json — Android App Links verification file.
  if (base === 'digital-asset-links.json') return true

  // assetlinks.json — common Android App Links filename. Gated on .well-known/
  // dir context since the name could be reused in other contexts.
  if (base === 'assetlinks.json' && pathLower.includes('.well-known/')) return true

  return false
}

// ---------------------------------------------------------------------------
// Detection helpers — MOBILE_PLATFORM_CONFIG_DRIFT
// ---------------------------------------------------------------------------

function isMobilePlatformConfig(pathLower: string, base: string): boolean {
  // eas.json — Expo Application Services: manages code signing credentials,
  // push notification keys, and build profiles for React Native/Expo apps.
  if (base === 'eas.json') return true

  // capacitor.config.json / capacitor.config.ts — Ionic Capacitor mobile app
  // config: native platform settings, plugin config, and server URL.
  if (base === 'capacitor.config.json' || base === 'capacitor.config.ts') return true

  // ionic.config.json — Ionic Framework project config.
  if (base === 'ionic.config.json') return true

  // Podfile.lock — CocoaPods lockfile for iOS/macOS. Records exact pod versions
  // and checksums. Not covered by WS-58 (which handles npm/cargo/go/python/ruby).
  // CocoaPods is exclusively an Apple platform tool — globally unambiguous.
  if (base === 'podfile.lock') return true

  // .xcconfig — Xcode build configuration files. Set code signing identity and
  // provisioning profile. Gated on iOS/Apple dirs since .xcconfig files can appear
  // in other toolchains.
  if (base.endsWith('.xcconfig')) {
    for (const dir of IOS_DIRS) {
      if (pathLower.includes(dir)) return true
    }
  }

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

type MobileAppSecurityRule = {
  id: MobileAppSecurityRuleId
  severity: MobileAppSecuritySeverity
  description: string
  recommendation: string
  matches: (pathLower: string, base: string, ext: string) => boolean
}

export const MOBILE_APP_SECURITY_RULES: readonly MobileAppSecurityRule[] = [
  {
    id: 'IOS_ENTITLEMENTS_DRIFT',
    severity: 'high',
    description: 'iOS, macOS, watchOS, or tvOS app entitlement files or code signing export options were modified. Entitlement files define what Apple platform capabilities an app is granted at runtime — keychain access groups, HealthKit read/write permissions, iCloud container identifiers, push notification entitlements, NFC tag reader access, and Apple Pay merchant identifiers. Overly broad entitlements expand the blast radius of a compromised app; removed entitlements may silently break security-critical features.',
    recommendation: 'Review the entitlement diff to confirm no new sensitive capabilities were added (e.g., keychain-access-groups expanded to include other apps, com.apple.developer.healthkit.background-delivery added). Verify that ExportOptions.plist changes do not switch the distribution method from app-store to enterprise or ad-hoc without authorization. Entitlement changes must be approved by the security team before App Store submission.',
    matches: (p, b) => isIosEntitlementsFile(p, b),
  },
  {
    id: 'ANDROID_MANIFEST_DRIFT',
    severity: 'high',
    description: 'The Android application manifest (AndroidManifest.xml) was modified. The main manifest is the authoritative source for declared permissions (READ_CONTACTS, CAMERA, ACCESS_FINE_LOCATION), exported components (Activity/Service/BroadcastReceiver/ContentProvider with android:exported="true"), the android:debuggable flag, backup settings (android:allowBackup, android:dataExtractionRules), and the network security config reference. Changes can silently expose components to third-party apps, add dangerous permissions, enable ADB-level debugging in non-debug builds, or expand data backup scope.',
    recommendation: 'Verify that no new android:exported="true" attributes were added to components that should be private, that newly declared permissions are genuinely required and of minimum necessary scope (COARSE vs FINE location), that android:debuggable was not set to true outside of debug build types, and that android:allowBackup was not enabled without a corresponding data-extraction-rules file restricting backup scope. Manifest changes require security team sign-off before release.',
    matches: (p, _b, _e) => isAndroidManifestSecurityFile(p),
  },
  {
    id: 'MOBILE_SIGNING_CONFIG_DRIFT',
    severity: 'high',
    description: 'Mobile app code signing configuration files were modified — iOS provisioning profiles (.mobileprovision), Android signing keystores (.jks/.keystore), or signing property files (signing.properties, keystore.properties, key.properties). Provisioning profiles define which entitlements an iOS app receives and which distribution channels it can use. Android keystore files contain the private key that proves app authorship; committing them to version control risks permanent signing key compromise and unauthorized app publication.',
    recommendation: 'If a .jks or .keystore file was added, remove it from the repository immediately and rotate the signing key — committed keystores must be treated as compromised. For signing.properties or keystore.properties, verify that no passwords or key aliases are stored in plaintext (use environment variables or CI/CD secret stores instead). Provisioning profile changes should be audited to confirm the profile covers only the intended bundle IDs and distribution entitlements.',
    matches: (p, b) => isMobileSigningConfig(p, b),
  },
  {
    id: 'IOS_APP_SECURITY_CONFIG_DRIFT',
    severity: 'high',
    description: 'iOS/macOS application security configuration property lists were modified — Info.plist (App Transport Security exceptions, privacy usage strings, URL scheme registrations), PrivacyInfo.xcprivacy (Apple Privacy Manifest), or ATS.plist. Info.plist changes can add NSAllowsArbitraryLoads exceptions that disable TLS enforcement for all network connections, register URL schemes that intercept links from other apps, or add privacy strings for newly requested sensor access. PrivacyInfo.xcprivacy changes may affect App Store compliance for SDK privacy manifests.',
    recommendation: 'Review Info.plist changes for NSAppTransportSecurity modifications — NSAllowsArbitraryLoads: true disables ATS globally and requires security team approval. Verify that newly added NSExceptionDomains do not use wildcards covering payment or auth domains. Confirm that CFBundleURLTypes changes do not register URL schemes that intercept OAuth callbacks or payment deep links. PrivacyInfo.xcprivacy changes must list valid purpose codes for all declared privacy-sensitive API categories.',
    matches: (p, b) => isIosAppSecurityConfig(p, b),
  },
  {
    id: 'ANDROID_OBFUSCATION_CONFIG_DRIFT',
    severity: 'medium',
    description: 'Android ProGuard or R8 code obfuscation and shrinking rule files were modified. ProGuard/R8 rules control which classes, methods, and fields are kept, renamed, or removed during the release build. Weakened or disabled obfuscation exposes security-critical logic in the app binary — authentication token handling, license validation, anti-tampering checks, and API key obfuscation become trivially reversible. Keep rules that prevent shrinking of security validation code are a common misconfiguration vector.',
    recommendation: 'Verify that no -keep rules were added that expose security-critical class names or method signatures in the final binary. Confirm that -dontobfuscate was not added, which disables renaming entirely. Consumer rules published with a library should not prevent downstream apps from applying their own obfuscation. Consider using -keepnames sparingly and only for classes that need stable signatures for serialization, not for security logic.',
    matches: (p, b) => isAndroidObfuscationConfig(p, b),
  },
  {
    id: 'MOBILE_FIREBASE_CONFIG_DRIFT',
    severity: 'medium',
    description: 'Firebase or Google services configuration files for a mobile app were modified — google-services.json (Android), GoogleService-Info.plist (iOS), firebase.json, .firebaserc, or files in a firebase/ directory. These files contain the Firebase project ID, API keys, database URLs, storage bucket names, OAuth client IDs, and push notification sender IDs. Changes can point the app at a different Firebase project, and projects with permissive Firestore/Realtime Database security rules can expose all user data.',
    recommendation: 'Verify that the Firebase project ID still points to the correct environment (dev/staging/prod) and has not been swapped to a project with permissive rules. If firebase.json was modified, review Firestore and Realtime Database rules for any relaxation of read/write permissions. Confirm that .firebaserc project aliases match the expected deployment targets. Check that google-services.json API key restrictions are still configured in the Google Cloud Console.',
    matches: (p, b) => isMobileFirebaseConfig(p, b),
  },
  {
    id: 'MOBILE_DEEP_LINK_CONFIG_DRIFT',
    severity: 'medium',
    description: 'Mobile deep link verification configuration files were modified — apple-app-site-association (iOS Universal Links), assetlinks.json or digital-asset-links.json (Android App Links). These files, hosted at /.well-known/ on a web server, establish verified associations between a domain and a mobile app so the OS routes matching URLs directly into the app. Misconfiguration enables link hijacking — a malicious app can intercept payment callbacks, OAuth redirect URIs, password reset links, and authentication deep links.',
    recommendation: 'Verify that apple-app-site-association path patterns still match only the intended URL paths and do not include wildcards covering payment or auth callback paths unnecessarily. For assetlinks.json, confirm that sha256_cert_fingerprints contains only the production signing certificate fingerprint and has not been extended to include development or compromised certificates. Deep link verification file changes must be reviewed by the security team before deploying to production web servers.',
    matches: (p, b) => isMobileDeepLinkConfig(p, b),
  },
  {
    id: 'MOBILE_PLATFORM_CONFIG_DRIFT',
    severity: 'low',
    description: 'Mobile platform or cross-platform framework configuration files were modified — Expo Application Services config (eas.json), Ionic Capacitor config (capacitor.config.json/ts), Ionic Framework config (ionic.config.json), CocoaPods lockfile (Podfile.lock), or Xcode build configuration files (.xcconfig). EAS config changes affect which credentials are used for code signing and push notifications. Podfile.lock changes indicate iOS dependency version changes that may introduce vulnerable pod versions. Xcconfig changes can override code signing identity or provisioning profile.',
    recommendation: 'For eas.json changes, verify that credential source was not changed from remote to local (which bypasses EAS-managed certificate rotation) and that new build profiles do not relax distribution method restrictions. For Podfile.lock changes, check whether any pods were downgraded to versions with known CVEs or their checksums were modified (indicating potential supply chain tampering). For .xcconfig changes, verify that CODE_SIGN_IDENTITY and PROVISIONING_PROFILE settings target the expected signing identity and profile.',
    matches: (p, b) => isMobilePlatformConfig(p, b),
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

function penaltyFor(sev: MobileAppSecuritySeverity, count: number): number {
  switch (sev) {
    case 'high':   return Math.min(count * HIGH_PENALTY_PER, HIGH_PENALTY_CAP)
    case 'medium': return Math.min(count * MED_PENALTY_PER,  MED_PENALTY_CAP)
    case 'low':    return Math.min(count * LOW_PENALTY_PER,  LOW_PENALTY_CAP)
  }
}

function toRiskLevel(score: number): MobileAppSecurityRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanMobileAppSecurityDrift(filePaths: string[]): MobileAppSecurityDriftResult {
  if (filePaths.length === 0) return emptyResult()

  const paths = filePaths
    .map((p) => p.replace(/\\/g, '/'))
    .filter((p) => {
      const lower = p.toLowerCase()
      return !VENDOR_DIRS.some((d) => lower.includes(d))
    })

  if (paths.length === 0) return emptyResult()

  const accumulated = new Map<MobileAppSecurityRuleId, { firstPath: string; count: number }>()

  for (const path of paths) {
    const pathLower = path.toLowerCase()
    const base = pathLower.split('/').at(-1) ?? pathLower
    const ext  = base.includes('.') ? `.${base.split('.').at(-1)}` : ''

    for (const rule of MOBILE_APP_SECURITY_RULES) {
      if (rule.matches(pathLower, base, ext)) {
        const existing = accumulated.get(rule.id)
        if (existing) {
          existing.count += 1
        } else {
          accumulated.set(rule.id, { firstPath: path, count: 1 })
        }
      }
    }
  }

  if (accumulated.size === 0) return emptyResult()

  const SEVERITY_ORDER: Record<MobileAppSecuritySeverity, number> = { high: 0, medium: 1, low: 2 }
  const findings: MobileAppSecurityDriftFinding[] = []

  for (const rule of MOBILE_APP_SECURITY_RULES) {
    const match = accumulated.get(rule.id)
    if (!match) continue
    findings.push({
      ruleId:         rule.id,
      severity:       rule.severity,
      matchedPath:    match.firstPath,
      matchCount:     match.count,
      description:    rule.description,
      recommendation: rule.recommendation,
    })
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])

  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  let rawScore = 0
  for (const finding of findings) {
    rawScore += penaltyFor(finding.severity, finding.matchCount)
  }
  const riskScore = Math.min(rawScore, 100)
  const riskLevel = toRiskLevel(riskScore)

  const summary = buildSummary(riskLevel, highCount, mediumCount, lowCount, findings)

  return {
    riskScore,
    riskLevel,
    totalFindings: findings.length,
    highCount,
    mediumCount,
    lowCount,
    findings,
    summary,
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emptyResult(): MobileAppSecurityDriftResult {
  return {
    riskScore: 0,
    riskLevel: 'none',
    totalFindings: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    findings: [],
    summary: 'No mobile application security configuration drift detected.',
  }
}

function buildSummary(
  level: MobileAppSecurityRiskLevel,
  high: number,
  medium: number,
  low: number,
  findings: MobileAppSecurityDriftFinding[],
): string {
  if (level === 'none') return 'No mobile application security configuration drift detected.'

  const parts: string[] = []
  if (high > 0)   parts.push(`${high} high`)
  if (medium > 0) parts.push(`${medium} medium`)
  if (low > 0)    parts.push(`${low} low`)

  const topRule  = findings[0]
  const topLabel = topRule ? topRule.ruleId.replace(/_/g, ' ').toLowerCase() : 'mobile security config'

  return `Mobile application security drift detected (${parts.join(', ')} finding${findings.length !== 1 ? 's' : ''}). Most prominent: ${topLabel}. Review changes to ensure entitlements, manifest permissions, signing credentials, and platform security configs remain within authorized boundaries.`
}
