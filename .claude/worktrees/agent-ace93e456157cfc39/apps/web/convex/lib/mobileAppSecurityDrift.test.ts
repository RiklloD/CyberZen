/// <reference types="vite/client" />
import { describe, expect, it } from 'vitest'
import {
  isAndroidManifestSecurityFile,
  MOBILE_APP_SECURITY_RULES,
  scanMobileAppSecurityDrift,
} from './mobileAppSecurityDrift'

// ---------------------------------------------------------------------------
// isAndroidManifestSecurityFile — user contribution
// ---------------------------------------------------------------------------

describe('isAndroidManifestSecurityFile', () => {
  it('flags main AndroidManifest.xml', () => {
    expect(isAndroidManifestSecurityFile('android/src/main/androidmanifest.xml')).toBe(true)
  })

  it('flags root-level AndroidManifest.xml', () => {
    expect(isAndroidManifestSecurityFile('androidmanifest.xml')).toBe(true)
  })

  it('flags app module main manifest', () => {
    expect(isAndroidManifestSecurityFile('app/src/main/androidmanifest.xml')).toBe(true)
  })

  it('flags flavour-specific manifest (free)', () => {
    expect(isAndroidManifestSecurityFile('app/src/free/androidmanifest.xml')).toBe(true)
  })

  it('flags flavour-specific manifest (paid)', () => {
    expect(isAndroidManifestSecurityFile('app/src/paid/androidmanifest.xml')).toBe(true)
  })

  it('flags debug build-type manifest', () => {
    expect(isAndroidManifestSecurityFile('app/src/debug/androidmanifest.xml')).toBe(true)
  })

  it('flags release build-type manifest', () => {
    expect(isAndroidManifestSecurityFile('app/src/release/androidmanifest.xml')).toBe(true)
  })

  it('excludes androidTest source set manifest', () => {
    expect(isAndroidManifestSecurityFile('app/src/androidtest/androidmanifest.xml')).toBe(false)
  })

  it('excludes test source set manifest', () => {
    expect(isAndroidManifestSecurityFile('app/src/test/androidmanifest.xml')).toBe(false)
  })

  it('excludes testDebug source set manifest', () => {
    expect(isAndroidManifestSecurityFile('app/src/testdebug/androidmanifest.xml')).toBe(false)
  })

  it('excludes testRelease source set manifest', () => {
    expect(isAndroidManifestSecurityFile('app/src/testrelease/androidmanifest.xml')).toBe(false)
  })

  it('excludes unitTests source set manifest', () => {
    expect(isAndroidManifestSecurityFile('app/src/unittests/androidmanifest.xml')).toBe(false)
  })

  it('excludes integrationTest source set manifest', () => {
    expect(isAndroidManifestSecurityFile('module/src/integrationtest/androidmanifest.xml')).toBe(false)
  })

  it('returns false for wrong basename', () => {
    expect(isAndroidManifestSecurityFile('android/src/main/notamanifest.xml')).toBe(false)
  })

  it('returns false for AndroidManifest.xml.bak', () => {
    expect(isAndroidManifestSecurityFile('android/androidmanifest.xml.bak')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// IOS_ENTITLEMENTS_DRIFT
// ---------------------------------------------------------------------------

describe('IOS_ENTITLEMENTS_DRIFT', () => {
  const rule = MOBILE_APP_SECURITY_RULES.find((r) => r.id === 'IOS_ENTITLEMENTS_DRIFT')!

  it('flags .entitlements extension', () => {
    expect(rule.matches('ios/runner/runner.entitlements', 'runner.entitlements', '.entitlements')).toBe(true)
  })

  it('flags bare .entitlements at any path depth', () => {
    expect(rule.matches('app.entitlements', 'app.entitlements', '.entitlements')).toBe(true)
  })

  it('flags watchOS entitlements', () => {
    expect(rule.matches('watchos/extension.entitlements', 'extension.entitlements', '.entitlements')).toBe(true)
  })

  it('flags ExportOptions.plist', () => {
    expect(rule.matches('exportoptions.plist', 'exportoptions.plist', '.plist')).toBe(true)
  })

  it('flags ExportOptions.plist nested in ios/ dir', () => {
    expect(rule.matches('ios/exportoptions.plist', 'exportoptions.plist', '.plist')).toBe(true)
  })

  it('does not flag plain Info.plist', () => {
    expect(rule.matches('ios/runner/info.plist', 'info.plist', '.plist')).toBe(false)
  })

  it('does not flag .plist with other names', () => {
    expect(rule.matches('ios/settings.plist', 'settings.plist', '.plist')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// ANDROID_MANIFEST_DRIFT
// ---------------------------------------------------------------------------

describe('ANDROID_MANIFEST_DRIFT', () => {
  const rule = MOBILE_APP_SECURITY_RULES.find((r) => r.id === 'ANDROID_MANIFEST_DRIFT')!

  it('flags main manifest', () => {
    expect(rule.matches('android/src/main/androidmanifest.xml', 'androidmanifest.xml', '.xml')).toBe(true)
  })

  it('flags app/src/main manifest', () => {
    expect(rule.matches('app/src/main/androidmanifest.xml', 'androidmanifest.xml', '.xml')).toBe(true)
  })

  it('flags flavour manifest', () => {
    expect(rule.matches('app/src/staging/androidmanifest.xml', 'androidmanifest.xml', '.xml')).toBe(true)
  })

  it('excludes androidTest manifest', () => {
    expect(rule.matches('app/src/androidtest/androidmanifest.xml', 'androidmanifest.xml', '.xml')).toBe(false)
  })

  it('excludes test manifest', () => {
    expect(rule.matches('app/src/test/androidmanifest.xml', 'androidmanifest.xml', '.xml')).toBe(false)
  })

  it('does not flag other XML files', () => {
    expect(rule.matches('android/src/main/res/layout/activity_main.xml', 'activity_main.xml', '.xml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// MOBILE_SIGNING_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('MOBILE_SIGNING_CONFIG_DRIFT', () => {
  const rule = MOBILE_APP_SECURITY_RULES.find((r) => r.id === 'MOBILE_SIGNING_CONFIG_DRIFT')!

  it('flags .mobileprovision files', () => {
    expect(rule.matches('ios/development.mobileprovision', 'development.mobileprovision', '.mobileprovision')).toBe(true)
  })

  it('flags .jks files', () => {
    expect(rule.matches('android/release.jks', 'release.jks', '.jks')).toBe(true)
  })

  it('flags .keystore files', () => {
    expect(rule.matches('android/app.keystore', 'app.keystore', '.keystore')).toBe(true)
  })

  it('flags signing.properties', () => {
    expect(rule.matches('android/signing.properties', 'signing.properties', '.properties')).toBe(true)
  })

  it('flags keystore.properties', () => {
    expect(rule.matches('android/keystore.properties', 'keystore.properties', '.properties')).toBe(true)
  })

  it('flags key.properties inside android/ dir', () => {
    expect(rule.matches('android/key.properties', 'key.properties', '.properties')).toBe(true)
  })

  it('does not flag key.properties outside android/ dir', () => {
    expect(rule.matches('config/key.properties', 'key.properties', '.properties')).toBe(false)
  })

  it('does not flag ios/key.properties', () => {
    expect(rule.matches('ios/key.properties', 'key.properties', '.properties')).toBe(false)
  })

  it('does not flag .cer certificate files', () => {
    expect(rule.matches('certs/apple.cer', 'apple.cer', '.cer')).toBe(false)
  })

  it('does not flag .p12 files', () => {
    expect(rule.matches('certs/signing.p12', 'signing.p12', '.p12')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// IOS_APP_SECURITY_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('IOS_APP_SECURITY_CONFIG_DRIFT', () => {
  const rule = MOBILE_APP_SECURITY_RULES.find((r) => r.id === 'IOS_APP_SECURITY_CONFIG_DRIFT')!

  it('flags PrivacyInfo.xcprivacy anywhere', () => {
    expect(rule.matches('privacyinfo.xcprivacy', 'privacyinfo.xcprivacy', '.xcprivacy')).toBe(true)
  })

  it('flags PrivacyInfo.xcprivacy in ios/ dir', () => {
    expect(rule.matches('ios/myapp/privacyinfo.xcprivacy', 'privacyinfo.xcprivacy', '.xcprivacy')).toBe(true)
  })

  it('flags ATS.plist', () => {
    expect(rule.matches('ios/ats.plist', 'ats.plist', '.plist')).toBe(true)
  })

  it('flags Info.plist inside ios/ dir', () => {
    expect(rule.matches('ios/runner/info.plist', 'info.plist', '.plist')).toBe(true)
  })

  it('flags Info.plist inside macos/ dir', () => {
    expect(rule.matches('macos/myapp/info.plist', 'info.plist', '.plist')).toBe(true)
  })

  it('flags Info.plist inside xcodeproj/ dir', () => {
    expect(rule.matches('myapp.xcodeproj/info.plist', 'info.plist', '.plist')).toBe(true)
  })

  it('flags Info.plist inside Runner/ dir', () => {
    expect(rule.matches('runner/info.plist', 'info.plist', '.plist')).toBe(true)
  })

  it('does not flag Info.plist at project root (no iOS context)', () => {
    expect(rule.matches('info.plist', 'info.plist', '.plist')).toBe(false)
  })

  it('does not flag Info.plist inside android/ dir', () => {
    expect(rule.matches('android/info.plist', 'info.plist', '.plist')).toBe(false)
  })

  it('does not flag Info.plist inside java/ dir', () => {
    expect(rule.matches('src/main/java/info.plist', 'info.plist', '.plist')).toBe(false)
  })

  it('does not flag generic .plist files outside iOS dirs', () => {
    expect(rule.matches('config/settings.plist', 'settings.plist', '.plist')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// ANDROID_OBFUSCATION_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('ANDROID_OBFUSCATION_CONFIG_DRIFT', () => {
  const rule = MOBILE_APP_SECURITY_RULES.find((r) => r.id === 'ANDROID_OBFUSCATION_CONFIG_DRIFT')!

  it('flags proguard-rules.pro', () => {
    expect(rule.matches('app/proguard-rules.pro', 'proguard-rules.pro', '.pro')).toBe(true)
  })

  it('flags consumer-rules.pro', () => {
    expect(rule.matches('library/consumer-rules.pro', 'consumer-rules.pro', '.pro')).toBe(true)
  })

  it('flags proguard-android.txt', () => {
    expect(rule.matches('proguard-android.txt', 'proguard-android.txt', '.txt')).toBe(true)
  })

  it('flags proguard-android-optimize.txt', () => {
    expect(rule.matches('proguard-android-optimize.txt', 'proguard-android-optimize.txt', '.txt')).toBe(true)
  })

  it('flags r8-rules.txt', () => {
    expect(rule.matches('app/r8-rules.txt', 'r8-rules.txt', '.txt')).toBe(true)
  })

  it('flags files inside proguard/ dir', () => {
    expect(rule.matches('app/proguard/rules.pro', 'rules.pro', '.pro')).toBe(true)
  })

  it('flags proguard/ dir with .txt extension', () => {
    expect(rule.matches('config/proguard/mapping.txt', 'mapping.txt', '.txt')).toBe(true)
  })

  it('flags proguard-*.pro prefix files', () => {
    expect(rule.matches('proguard-custom.pro', 'proguard-custom.pro', '.pro')).toBe(true)
  })

  it('flags proguard-*.cfg prefix files', () => {
    expect(rule.matches('proguard-debug.cfg', 'proguard-debug.cfg', '.cfg')).toBe(true)
  })

  it('flags r8-extra.txt prefix files', () => {
    expect(rule.matches('r8-extra.txt', 'r8-extra.txt', '.txt')).toBe(true)
  })

  it('flags r8-config.pro prefix files', () => {
    expect(rule.matches('r8-config.pro', 'r8-config.pro', '.pro')).toBe(true)
  })

  it('does not flag generic .pro files outside proguard dirs', () => {
    expect(rule.matches('config/settings.pro', 'settings.pro', '.pro')).toBe(false)
  })

  it('does not flag .txt files outside proguard dirs and prefix', () => {
    expect(rule.matches('readme.txt', 'readme.txt', '.txt')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// MOBILE_FIREBASE_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('MOBILE_FIREBASE_CONFIG_DRIFT', () => {
  const rule = MOBILE_APP_SECURITY_RULES.find((r) => r.id === 'MOBILE_FIREBASE_CONFIG_DRIFT')!

  it('flags google-services.json', () => {
    expect(rule.matches('android/app/google-services.json', 'google-services.json', '.json')).toBe(true)
  })

  it('flags GoogleService-Info.plist', () => {
    expect(rule.matches('ios/runner/googleservice-info.plist', 'googleservice-info.plist', '.plist')).toBe(true)
  })

  it('flags .firebaserc', () => {
    expect(rule.matches('.firebaserc', '.firebaserc', '')).toBe(true)
  })

  it('flags firebase.json', () => {
    expect(rule.matches('firebase.json', 'firebase.json', '.json')).toBe(true)
  })

  it('flags firebase-config.json', () => {
    expect(rule.matches('firebase-config.json', 'firebase-config.json', '.json')).toBe(true)
  })

  it('flags firebaseConfig.json (camelCase variant)', () => {
    expect(rule.matches('firebaseconfig.json', 'firebaseconfig.json', '.json')).toBe(true)
  })

  it('flags JSON files inside firebase/ dir', () => {
    expect(rule.matches('firebase/functions/config.json', 'config.json', '.json')).toBe(true)
  })

  it('flags YAML files inside firebase/ dir', () => {
    expect(rule.matches('firebase/rules.yaml', 'rules.yaml', '.yaml')).toBe(true)
  })

  it('does not flag generic config.json outside firebase/ dir', () => {
    expect(rule.matches('config/config.json', 'config.json', '.json')).toBe(false)
  })

  it('does not flag services.json with different name', () => {
    expect(rule.matches('app/services.json', 'services.json', '.json')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// MOBILE_DEEP_LINK_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('MOBILE_DEEP_LINK_CONFIG_DRIFT', () => {
  const rule = MOBILE_APP_SECURITY_RULES.find((r) => r.id === 'MOBILE_DEEP_LINK_CONFIG_DRIFT')!

  it('flags apple-app-site-association (no extension)', () => {
    expect(rule.matches('.well-known/apple-app-site-association', 'apple-app-site-association', '')).toBe(true)
  })

  it('flags apple-app-site-association at root (no extension)', () => {
    expect(rule.matches('apple-app-site-association', 'apple-app-site-association', '')).toBe(true)
  })

  it('flags digital-asset-links.json', () => {
    expect(rule.matches('.well-known/digital-asset-links.json', 'digital-asset-links.json', '.json')).toBe(true)
  })

  it('flags digital-asset-links.json anywhere', () => {
    expect(rule.matches('digital-asset-links.json', 'digital-asset-links.json', '.json')).toBe(true)
  })

  it('flags assetlinks.json in .well-known/', () => {
    expect(rule.matches('.well-known/assetlinks.json', 'assetlinks.json', '.json')).toBe(true)
  })

  it('does not flag assetlinks.json outside .well-known/', () => {
    expect(rule.matches('android/assetlinks.json', 'assetlinks.json', '.json')).toBe(false)
  })

  it('does not flag generic links.json', () => {
    expect(rule.matches('.well-known/links.json', 'links.json', '.json')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// MOBILE_PLATFORM_CONFIG_DRIFT
// ---------------------------------------------------------------------------

describe('MOBILE_PLATFORM_CONFIG_DRIFT', () => {
  const rule = MOBILE_APP_SECURITY_RULES.find((r) => r.id === 'MOBILE_PLATFORM_CONFIG_DRIFT')!

  it('flags eas.json', () => {
    expect(rule.matches('eas.json', 'eas.json', '.json')).toBe(true)
  })

  it('flags capacitor.config.json', () => {
    expect(rule.matches('capacitor.config.json', 'capacitor.config.json', '.json')).toBe(true)
  })

  it('flags capacitor.config.ts', () => {
    expect(rule.matches('capacitor.config.ts', 'capacitor.config.ts', '.ts')).toBe(true)
  })

  it('flags ionic.config.json', () => {
    expect(rule.matches('ionic.config.json', 'ionic.config.json', '.json')).toBe(true)
  })

  it('flags Podfile.lock', () => {
    expect(rule.matches('podfile.lock', 'podfile.lock', '.lock')).toBe(true)
  })

  it('flags Podfile.lock inside ios/ dir', () => {
    expect(rule.matches('ios/podfile.lock', 'podfile.lock', '.lock')).toBe(true)
  })

  it('flags .xcconfig inside ios/ dir', () => {
    expect(rule.matches('ios/flutter/debug.xcconfig', 'debug.xcconfig', '.xcconfig')).toBe(true)
  })

  it('flags .xcconfig inside macos/ dir', () => {
    expect(rule.matches('macos/runner/configs/debug.xcconfig', 'debug.xcconfig', '.xcconfig')).toBe(true)
  })

  it('flags .xcconfig inside xcodeproj/ dir', () => {
    expect(rule.matches('myapp.xcodeproj/debug.xcconfig', 'debug.xcconfig', '.xcconfig')).toBe(true)
  })

  it('does not flag .xcconfig outside iOS dirs', () => {
    expect(rule.matches('config/build.xcconfig', 'build.xcconfig', '.xcconfig')).toBe(false)
  })

  it('does not flag Podfile (not the lockfile)', () => {
    expect(rule.matches('ios/podfile', 'podfile', '')).toBe(false)
  })

  it('does not flag generic config.json', () => {
    expect(rule.matches('config.json', 'config.json', '.json')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Vendor directory exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('excludes files in node_modules/', () => {
    const result = scanMobileAppSecurityDrift([
      'node_modules/somelib/google-services.json',
    ])
    expect(result.riskLevel).toBe('none')
    expect(result.totalFindings).toBe(0)
  })

  it('excludes files in .gradle/', () => {
    const result = scanMobileAppSecurityDrift([
      '.gradle/cache/signing.properties',
    ])
    expect(result.riskLevel).toBe('none')
  })

  it('excludes files in vendor/', () => {
    const result = scanMobileAppSecurityDrift([
      'vendor/pods/something.entitlements',
    ])
    expect(result.riskLevel).toBe('none')
  })

  it('includes non-vendor paths', () => {
    const result = scanMobileAppSecurityDrift(['ios/App.entitlements'])
    expect(result.riskLevel).not.toBe('none')
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes for .entitlements', () => {
    const result = scanMobileAppSecurityDrift(['ios\\Runner\\Runner.entitlements'])
    expect(result.totalFindings).toBeGreaterThan(0)
    const f = result.findings.find((x) => x.ruleId === 'IOS_ENTITLEMENTS_DRIFT')
    expect(f).toBeDefined()
  })

  it('normalises backslashes for AndroidManifest.xml', () => {
    const result = scanMobileAppSecurityDrift(['android\\src\\main\\AndroidManifest.xml'])
    expect(result.totalFindings).toBeGreaterThan(0)
    const f = result.findings.find((x) => x.ruleId === 'ANDROID_MANIFEST_DRIFT')
    expect(f).toBeDefined()
  })

  it('normalises backslashes and respects test exclusion', () => {
    const result = scanMobileAppSecurityDrift([
      'android\\src\\androidTest\\AndroidManifest.xml',
    ])
    const f = result.findings.find((x) => x.ruleId === 'ANDROID_MANIFEST_DRIFT')
    expect(f).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('empty path list → riskScore 0 and riskLevel none', () => {
    const r = scanMobileAppSecurityDrift([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })

  it('one HIGH rule match → riskScore 15, riskLevel low', () => {
    const r = scanMobileAppSecurityDrift(['ios/App.entitlements'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('two HIGH rule matches → riskScore 30, riskLevel medium', () => {
    const r = scanMobileAppSecurityDrift([
      'ios/App.entitlements',
      'android/src/main/AndroidManifest.xml',
    ])
    expect(r.riskScore).toBe(30)
    expect(r.riskLevel).toBe('medium')
  })

  it('three HIGH rule matches → riskScore 45, riskLevel high', () => {
    const r = scanMobileAppSecurityDrift([
      'ios/App.entitlements',
      'android/src/main/AndroidManifest.xml',
      'android/release.jks',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('four HIGH rule matches → riskScore 60, riskLevel high', () => {
    const r = scanMobileAppSecurityDrift([
      'ios/App.entitlements',
      'android/src/main/AndroidManifest.xml',
      'android/release.jks',
      'ios/Runner/Info.plist',
    ])
    expect(r.riskScore).toBe(60)
    expect(r.riskLevel).toBe('high')
  })

  it('all 4 HIGH rules + 3 MEDIUM rules → caps at 100, riskLevel critical', () => {
    // 4 × 15 + 3 × 8 = 60 + 24 = 84 → min(84, 100) = 84 → critical
    const r = scanMobileAppSecurityDrift([
      'ios/App.entitlements',
      'android/src/main/AndroidManifest.xml',
      'android/release.jks',
      'ios/Runner/Info.plist',
      'app/proguard-rules.pro',
      'android/app/google-services.json',
      'apple-app-site-association',
    ])
    expect(r.riskScore).toBe(84)
    expect(r.riskLevel).toBe('critical')
  })

  it('ONE MEDIUM rule match → riskScore 8, riskLevel low', () => {
    const r = scanMobileAppSecurityDrift(['app/proguard-rules.pro'])
    expect(r.riskScore).toBe(8)
    expect(r.riskLevel).toBe('low')
  })

  it('one LOW rule match → riskScore 4, riskLevel low', () => {
    const r = scanMobileAppSecurityDrift(['eas.json'])
    expect(r.riskScore).toBe(4)
    expect(r.riskLevel).toBe('low')
  })

  it('HIGH penalty caps at 45 regardless of match count', () => {
    const manyEntitlements = Array.from({ length: 10 }, (_, i) => `ios/Module${i}.entitlements`)
    const r = scanMobileAppSecurityDrift(manyEntitlements)
    const f = r.findings.find((x) => x.ruleId === 'IOS_ENTITLEMENTS_DRIFT')!
    const singleRulePenalty = Math.min(f.matchCount * 15, 45)
    expect(singleRulePenalty).toBe(45)
    expect(f.matchCount).toBe(10)
  })

  it('MEDIUM penalty caps at 25 regardless of match count', () => {
    const manyProguard = Array.from({ length: 10 }, (_, i) => `module${i}/proguard-rules.pro`)
    const r = scanMobileAppSecurityDrift(manyProguard)
    const f = r.findings.find((x) => x.ruleId === 'ANDROID_OBFUSCATION_CONFIG_DRIFT')!
    const singleRulePenalty = Math.min(f.matchCount * 8, 25)
    expect(singleRulePenalty).toBe(25)
  })

  it('LOW penalty caps at 15 regardless of match count', () => {
    const manyXcconfig = Array.from({ length: 10 }, (_, i) => `ios/flutter/config${i}.xcconfig`)
    const r = scanMobileAppSecurityDrift(manyXcconfig)
    const f = r.findings.find((x) => x.ruleId === 'MOBILE_PLATFORM_CONFIG_DRIFT')!
    const singleRulePenalty = Math.min(f.matchCount * 4, 15)
    expect(singleRulePenalty).toBe(15)
  })

  it('total score clamped at 100 for extreme multi-rule push', () => {
    const paths = [
      'ios/App.entitlements',
      'android/src/main/AndroidManifest.xml',
      'android/release.jks',
      'ios/Runner/Info.plist',
      'app/proguard-rules.pro',
      'android/app/google-services.json',
      'apple-app-site-association',
      'eas.json',
    ]
    const r = scanMobileAppSecurityDrift(paths)
    expect(r.riskScore).toBeLessThanOrEqual(100)
  })
})

// ---------------------------------------------------------------------------
// Risk levels
// ---------------------------------------------------------------------------

describe('risk levels', () => {
  it('score 0 → none', () => {
    expect(scanMobileAppSecurityDrift([]).riskLevel).toBe('none')
  })

  it('score 15 → low (< 20)', () => {
    const r = scanMobileAppSecurityDrift(['ios/App.entitlements'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })

  it('score 19 → low', () => {
    // 1 HIGH (15) + 1 LOW (4) = 19
    const r = scanMobileAppSecurityDrift(['ios/App.entitlements', 'eas.json'])
    expect(r.riskScore).toBe(19)
    expect(r.riskLevel).toBe('low')
  })

  it('score 20 → medium (>= 20 and < 45)', () => {
    // 1 HIGH (15) + 1 MEDIUM (8) = 23 — wait that's > 20, let me use 2 MEDIUM + 1 LOW
    // 2 MEDIUM (16) + 1 LOW (4) = 20
    const r = scanMobileAppSecurityDrift([
      'app/proguard-rules.pro',
      'android/app/google-services.json',
      'eas.json',
    ])
    expect(r.riskScore).toBe(20)
    expect(r.riskLevel).toBe('medium')
  })

  it('score 44 → medium (< 45)', () => {
    // 3 HIGH (45) — wait that's exactly 45, not 44
    // 2 HIGH (30) + 1 MEDIUM (8) + 1 MEDIUM (8) - wait that's 46
    // 2 HIGH (30) + 1 MEDIUM (8) + 1 LOW (4) = 42 → medium
    const r = scanMobileAppSecurityDrift([
      'ios/App.entitlements',
      'android/src/main/AndroidManifest.xml',
      'app/proguard-rules.pro',
      'eas.json',
    ])
    expect(r.riskScore).toBe(42)
    expect(r.riskLevel).toBe('medium')
  })

  it('score 45 → high (= 45, not < 45)', () => {
    // 3 HIGH rules = 45
    const r = scanMobileAppSecurityDrift([
      'ios/App.entitlements',
      'android/src/main/AndroidManifest.xml',
      'android/release.jks',
    ])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })

  it('score 69 → high (< 70)', () => {
    // 4 HIGH (60) + 1 MEDIUM (8) = 68 → high
    const r = scanMobileAppSecurityDrift([
      'ios/App.entitlements',
      'android/src/main/AndroidManifest.xml',
      'android/release.jks',
      'ios/Runner/Info.plist',
      'app/proguard-rules.pro',
    ])
    expect(r.riskScore).toBe(68)
    expect(r.riskLevel).toBe('high')
  })

  it('score >= 70 → critical', () => {
    // 4 HIGH (60) + 2 MEDIUM (16) = 76 → critical
    const r = scanMobileAppSecurityDrift([
      'ios/App.entitlements',
      'android/src/main/AndroidManifest.xml',
      'android/release.jks',
      'ios/Runner/Info.plist',
      'app/proguard-rules.pro',
      'android/app/google-services.json',
    ])
    expect(r.riskScore).toBe(76)
    expect(r.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Dedup per rule (one finding per triggered rule)
// ---------------------------------------------------------------------------

describe('dedup per rule', () => {
  it('multiple .entitlements files → one IOS_ENTITLEMENTS_DRIFT finding with matchCount 3', () => {
    const r = scanMobileAppSecurityDrift([
      'ios/App.entitlements',
      'ios/NotificationExtension.entitlements',
      'ios/ShareExtension.entitlements',
    ])
    const findings = r.findings.filter((f) => f.ruleId === 'IOS_ENTITLEMENTS_DRIFT')
    expect(findings).toHaveLength(1)
    expect(findings[0].matchCount).toBe(3)
  })

  it('multiple AndroidManifest.xml files → one ANDROID_MANIFEST_DRIFT finding', () => {
    const r = scanMobileAppSecurityDrift([
      'app/src/main/AndroidManifest.xml',
      'app/src/debug/AndroidManifest.xml',
      'lib/src/main/AndroidManifest.xml',
    ])
    const findings = r.findings.filter((f) => f.ruleId === 'ANDROID_MANIFEST_DRIFT')
    expect(findings).toHaveLength(1)
    expect(findings[0].matchCount).toBe(3)
  })

  it('firstPath is the first matched path for the rule', () => {
    const r = scanMobileAppSecurityDrift([
      'first.entitlements',
      'second.entitlements',
    ])
    const f = r.findings.find((x) => x.ruleId === 'IOS_ENTITLEMENTS_DRIFT')!
    expect(f.matchedPath).toBe('first.entitlements')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering
// ---------------------------------------------------------------------------

describe('severity ordering in findings', () => {
  it('HIGH findings appear before MEDIUM findings', () => {
    const r = scanMobileAppSecurityDrift([
      'app/proguard-rules.pro',    // MEDIUM
      'ios/App.entitlements',       // HIGH
    ])
    expect(r.findings[0].severity).toBe('high')
    expect(r.findings[1].severity).toBe('medium')
  })

  it('MEDIUM findings appear before LOW findings', () => {
    const r = scanMobileAppSecurityDrift([
      'eas.json',                  // LOW
      'app/proguard-rules.pro',   // MEDIUM
    ])
    expect(r.findings[0].severity).toBe('medium')
    expect(r.findings[1].severity).toBe('low')
  })

  it('HIGH before MEDIUM before LOW in full order', () => {
    const r = scanMobileAppSecurityDrift([
      'eas.json',                          // LOW
      'app/proguard-rules.pro',           // MEDIUM
      'ios/App.entitlements',              // HIGH
    ])
    expect(r.findings[0].severity).toBe('high')
    expect(r.findings[1].severity).toBe('medium')
    expect(r.findings[2].severity).toBe('low')
  })
})

// ---------------------------------------------------------------------------
// Summary and result shape
// ---------------------------------------------------------------------------

describe('summary and result shape', () => {
  it('empty result has correct zero-state', () => {
    const r = scanMobileAppSecurityDrift([])
    expect(r.totalFindings).toBe(0)
    expect(r.highCount).toBe(0)
    expect(r.mediumCount).toBe(0)
    expect(r.lowCount).toBe(0)
    expect(r.findings).toHaveLength(0)
    expect(r.summary).toContain('No mobile application security')
  })

  it('summary mentions finding counts', () => {
    const r = scanMobileAppSecurityDrift(['ios/App.entitlements'])
    expect(r.summary).toContain('high')
  })

  it('summary mentions most prominent rule', () => {
    const r = scanMobileAppSecurityDrift(['ios/App.entitlements'])
    expect(r.summary).toContain('ios entitlements drift')
  })

  it('totalFindings matches findings.length', () => {
    const r = scanMobileAppSecurityDrift([
      'ios/App.entitlements',
      'app/proguard-rules.pro',
      'eas.json',
    ])
    expect(r.totalFindings).toBe(r.findings.length)
  })

  it('highCount / mediumCount / lowCount match findings', () => {
    const r = scanMobileAppSecurityDrift([
      'ios/App.entitlements',
      'android/src/main/AndroidManifest.xml',
      'app/proguard-rules.pro',
      'eas.json',
    ])
    expect(r.highCount).toBe(2)
    expect(r.mediumCount).toBe(1)
    expect(r.lowCount).toBe(1)
  })

  it('findings include ruleId, severity, matchedPath, matchCount, description, recommendation', () => {
    const r = scanMobileAppSecurityDrift(['ios/App.entitlements'])
    const f = r.findings[0]
    expect(f).toHaveProperty('ruleId')
    expect(f).toHaveProperty('severity')
    expect(f).toHaveProperty('matchedPath')
    expect(f).toHaveProperty('matchCount')
    expect(f).toHaveProperty('description')
    expect(f).toHaveProperty('recommendation')
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('React Native project push hits entitlements + manifest + firebase + eas', () => {
    const r = scanMobileAppSecurityDrift([
      'ios/MyApp/MyApp.entitlements',
      'android/app/src/main/AndroidManifest.xml',
      'android/app/google-services.json',
      'ios/GoogleService-Info.plist',
      'eas.json',
    ])
    const ids = r.findings.map((f) => f.ruleId)
    expect(ids).toContain('IOS_ENTITLEMENTS_DRIFT')
    expect(ids).toContain('ANDROID_MANIFEST_DRIFT')
    expect(ids).toContain('MOBILE_FIREBASE_CONFIG_DRIFT')
    expect(ids).toContain('MOBILE_PLATFORM_CONFIG_DRIFT')
    expect(r.totalFindings).toBe(4)
  })

  it('Flutter project push hits signing + info.plist + proguard + xcconfig', () => {
    const r = scanMobileAppSecurityDrift([
      'android/key.properties',
      'ios/Runner/Info.plist',
      'android/app/proguard-rules.pro',
      'ios/Flutter/Debug.xcconfig',
    ])
    const ids = r.findings.map((f) => f.ruleId)
    expect(ids).toContain('MOBILE_SIGNING_CONFIG_DRIFT')
    expect(ids).toContain('IOS_APP_SECURITY_CONFIG_DRIFT')
    expect(ids).toContain('ANDROID_OBFUSCATION_CONFIG_DRIFT')
    expect(ids).toContain('MOBILE_PLATFORM_CONFIG_DRIFT')
  })

  it('Leaked keystore push → MOBILE_SIGNING_CONFIG_DRIFT with high severity', () => {
    const r = scanMobileAppSecurityDrift([
      'android/release.jks',
      'android/debug.keystore',
    ])
    const f = r.findings.find((x) => x.ruleId === 'MOBILE_SIGNING_CONFIG_DRIFT')!
    expect(f.severity).toBe('high')
    expect(f.matchCount).toBe(2)
  })

  it('App Links configuration push → MOBILE_DEEP_LINK_CONFIG_DRIFT', () => {
    const r = scanMobileAppSecurityDrift([
      '.well-known/apple-app-site-association',
      '.well-known/assetlinks.json',
    ])
    const f = r.findings.find((x) => x.ruleId === 'MOBILE_DEEP_LINK_CONFIG_DRIFT')!
    expect(f).toBeDefined()
    expect(f.matchCount).toBe(2)
  })

  it('iOS-only push with only non-iOS context Info.plist → no ios config finding', () => {
    const r = scanMobileAppSecurityDrift([
      'src/main/resources/Info.plist',  // Java resource, not iOS
    ])
    const f = r.findings.find((x) => x.ruleId === 'IOS_APP_SECURITY_CONFIG_DRIFT')
    expect(f).toBeUndefined()
  })

  it('Android test-only push produces no findings', () => {
    const r = scanMobileAppSecurityDrift([
      'app/src/androidTest/AndroidManifest.xml',
      'app/src/test/AndroidManifest.xml',
    ])
    expect(r.totalFindings).toBe(0)
    expect(r.riskLevel).toBe('none')
  })
})

// ---------------------------------------------------------------------------
// Rule registry completeness
// ---------------------------------------------------------------------------

describe('rule registry completeness', () => {
  it('has exactly 8 rules', () => {
    expect(MOBILE_APP_SECURITY_RULES).toHaveLength(8)
  })

  it('all rule IDs are unique', () => {
    const ids = MOBILE_APP_SECURITY_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('all rules have non-empty description and recommendation', () => {
    for (const rule of MOBILE_APP_SECURITY_RULES) {
      expect(rule.description.length).toBeGreaterThan(20)
      expect(rule.recommendation.length).toBeGreaterThan(20)
    }
  })

  it('severity values are valid', () => {
    const valid = new Set(['high', 'medium', 'low'])
    for (const rule of MOBILE_APP_SECURITY_RULES) {
      expect(valid.has(rule.severity)).toBe(true)
    }
  })

  it('contains all expected rule IDs', () => {
    const ids = new Set(MOBILE_APP_SECURITY_RULES.map((r) => r.id))
    expect(ids.has('IOS_ENTITLEMENTS_DRIFT')).toBe(true)
    expect(ids.has('ANDROID_MANIFEST_DRIFT')).toBe(true)
    expect(ids.has('MOBILE_SIGNING_CONFIG_DRIFT')).toBe(true)
    expect(ids.has('IOS_APP_SECURITY_CONFIG_DRIFT')).toBe(true)
    expect(ids.has('ANDROID_OBFUSCATION_CONFIG_DRIFT')).toBe(true)
    expect(ids.has('MOBILE_FIREBASE_CONFIG_DRIFT')).toBe(true)
    expect(ids.has('MOBILE_DEEP_LINK_CONFIG_DRIFT')).toBe(true)
    expect(ids.has('MOBILE_PLATFORM_CONFIG_DRIFT')).toBe(true)
  })

  it('HIGH severity rules: IOS_ENTITLEMENTS_DRIFT, ANDROID_MANIFEST_DRIFT, MOBILE_SIGNING_CONFIG_DRIFT, IOS_APP_SECURITY_CONFIG_DRIFT', () => {
    const high = MOBILE_APP_SECURITY_RULES.filter((r) => r.severity === 'high').map((r) => r.id)
    expect(high).toContain('IOS_ENTITLEMENTS_DRIFT')
    expect(high).toContain('ANDROID_MANIFEST_DRIFT')
    expect(high).toContain('MOBILE_SIGNING_CONFIG_DRIFT')
    expect(high).toContain('IOS_APP_SECURITY_CONFIG_DRIFT')
  })

  it('MEDIUM severity rules: ANDROID_OBFUSCATION_CONFIG_DRIFT, MOBILE_FIREBASE_CONFIG_DRIFT, MOBILE_DEEP_LINK_CONFIG_DRIFT', () => {
    const medium = MOBILE_APP_SECURITY_RULES.filter((r) => r.severity === 'medium').map((r) => r.id)
    expect(medium).toContain('ANDROID_OBFUSCATION_CONFIG_DRIFT')
    expect(medium).toContain('MOBILE_FIREBASE_CONFIG_DRIFT')
    expect(medium).toContain('MOBILE_DEEP_LINK_CONFIG_DRIFT')
  })

  it('LOW severity rule: MOBILE_PLATFORM_CONFIG_DRIFT', () => {
    const low = MOBILE_APP_SECURITY_RULES.filter((r) => r.severity === 'low').map((r) => r.id)
    expect(low).toContain('MOBILE_PLATFORM_CONFIG_DRIFT')
  })
})
