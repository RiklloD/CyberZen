/**
 * SIEM Export — pure payload builder library (no network, no Convex).
 *
 * Spec §4.6.5 — Observability + SIEM integration:
 *   Converts Blue Agent detection rule snapshots into ready-to-POST payloads
 *   for two target SIEM platforms:
 *
 *   Splunk HEC (HTTP Event Collector)
 *     POST /services/collector/event
 *     Auth: Authorization: Splunk <token>
 *     Body: newline-delimited JSON event objects
 *
 *   Elastic _bulk API
 *     POST /_bulk  (or POST /<index>/_bulk)
 *     Auth: Authorization: ApiKey <base64-key>
 *     Body: NDJSON — alternating action line + document line pairs
 *
 * Design: pure functions over snapshot data already stored in
 * `detectionRuleSnapshots`. Only the SPL rules are sent to Splunk and only
 * the KQL rules are sent to Elastic — each payload is formatted for its
 * native query language.
 *
 * Configuration (set in Convex env):
 *   SPLUNK_HEC_URL        e.g. https://splunk.internal:8088
 *   SPLUNK_HEC_TOKEN      Splunk HEC token
 *   SPLUNK_HEC_INDEX      default: sentinel_detection_rules
 *   ELASTIC_URL           e.g. https://elasticsearch.internal:9200
 *   ELASTIC_API_KEY       base64-encoded id:api_key  (Elastic API key format)
 *   ELASTIC_INDEX         default: sentinel-detection-rules
 */

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

export interface SiemRuleDoc {
  /** Original SPL / KQL query string from the Blue Agent rule. */
  rule_content: string
  /** 0-based position in the snapshot's rule array. */
  rule_index: number
  /** "splunk_spl" or "elastic_kql" */
  format: 'splunk_spl' | 'elastic_kql'
  /** Originating repository full name. */
  repository: string
  /** Unix epoch (ms) when the snapshot was generated. */
  generated_at: number
  /** Always "blue_agent" — identifies the Sentinel source. */
  sentinel_source: 'blue_agent'
}

// ---------------------------------------------------------------------------
// Splunk HEC
// ---------------------------------------------------------------------------

export interface SplunkHecEvent {
  /** The event document to index. */
  event: SiemRuleDoc
  /** Splunk sourcetype — useful for field extraction. */
  sourcetype: 'sentinel:detection_rule'
  /** Target Splunk index. */
  index: string
  /** Host label — set to the repository name. */
  host: string
}

/**
 * Build the Splunk HEC request body: newline-delimited JSON event objects.
 *
 * Splunk HEC supports batching multiple events in a single POST by separating
 * each JSON event object with a newline (`\n`). This is more efficient than
 * one HTTP call per rule and keeps the request atomic from HEC's perspective.
 *
 * @param splunkRules   The `splunkRules` string array from the snapshot.
 * @param repository    Repository full name (e.g. "acme/payments-api").
 * @param generatedAt   Snapshot generation timestamp (Unix ms).
 * @param index         Target Splunk index (default: "sentinel_detection_rules").
 * @returns Newline-delimited JSON string ready to POST to /services/collector/event.
 */
export function buildSplunkHecBody(
  splunkRules: string[],
  repository: string,
  generatedAt: number,
  index = 'sentinel_detection_rules',
): string {
  return splunkRules
    .map((ruleContent, ruleIndex) => {
      const event: SplunkHecEvent = {
        event: {
          rule_content: ruleContent,
          rule_index: ruleIndex,
          format: 'splunk_spl',
          repository,
          generated_at: generatedAt,
          sentinel_source: 'blue_agent',
        },
        sourcetype: 'sentinel:detection_rule',
        index,
        host: repository,
      }
      return JSON.stringify(event)
    })
    .join('\n')
}

// ---------------------------------------------------------------------------
// Elastic _bulk
// ---------------------------------------------------------------------------

/**
 * Build the Elastic `_bulk` request body: NDJSON action + document line pairs.
 *
 * Elastic _bulk format alternates between:
 *   { "index": { "_index": "<idx>", "_id": "<id>" } }   ← action line
 *   { ...document fields... }                             ← source document
 *
 * Each pair is separated by a newline and the body must end with a trailing
 * newline — Elastic rejects requests without it.
 *
 * @param elasticRules   The `elasticRules` string array from the snapshot.
 * @param repository     Repository full name.
 * @param generatedAt    Snapshot generation timestamp (Unix ms).
 * @param indexName      Target Elastic index (default: "sentinel-detection-rules").
 * @returns NDJSON string ready to POST to /_bulk.
 */
export function buildElasticBulkBody(
  elasticRules: string[],
  repository: string,
  generatedAt: number,
  indexName = 'sentinel-detection-rules',
): string {
  const lines: string[] = []

  for (let ruleIndex = 0; ruleIndex < elasticRules.length; ruleIndex++) {
    const docId = `${repository.replace(/\//g, '_')}_${generatedAt}_${ruleIndex}`

    // Action line
    const action = { index: { _index: indexName, _id: docId } }
    lines.push(JSON.stringify(action))

    // Document line
    const doc: SiemRuleDoc = {
      rule_content: elasticRules[ruleIndex],
      rule_index: ruleIndex,
      format: 'elastic_kql',
      repository,
      generated_at: generatedAt,
      sentinel_source: 'blue_agent',
    }
    lines.push(JSON.stringify(doc))
  }

  // Elastic _bulk requires a trailing newline
  return lines.join('\n') + (lines.length > 0 ? '\n' : '')
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/**
 * Returns true when the string looks like a valid absolute HTTP(S) URL.
 * Used to validate SIEM endpoint configuration before attempting a push.
 */
export function isValidSiemUrl(url: string): boolean {
  if (!url) return false
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:'
  } catch {
    return false
  }
}
