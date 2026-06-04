// WS-80 — Data Pipeline & ETL Security Configuration Drift Detector:
// pure computation library.
//
// Analyses the list of changed file paths from a push event for modifications
// to data pipeline and ETL security configuration files. This scanner focuses
// on the *data processing layer* — configurations that govern how analytics
// workloads authenticate to databases and data stores, encrypt data in transit,
// and control access to transformation and orchestration infrastructure.
//
// DISTINCT from:
//   WS-62  cloudSecurityDrift       — cloud IAM resource policies and KMS key
//                                     policies; WS-80 covers the data pipeline
//                                     tool configuration files themselves
//   WS-64  databaseSecurityDrift    — database server auth configs (pg_hba.conf,
//                                     my.cnf); WS-80 covers the client-side
//                                     connection profiles that pipeline tools
//                                     use to connect to those servers
//   WS-70  identityAccessDrift      — identity provider and PAM configs;
//                                     WS-80 covers pipeline-tool auth settings
//   WS-78  messagingSecurityDrift   — message broker configs (Kafka, RabbitMQ);
//                                     WS-80 covers data pipeline orchestration
//                                     and ETL transformation security settings
//
// Covered rule groups (8 rules):
//
//   AIRFLOW_SECURITY_DRIFT           — Apache Airflow webserver auth, RBAC,
//                                      and API security configuration
//   SPARK_SECURITY_DRIFT             — Apache Spark encryption, authentication,
//                                      and network security settings
//   DBT_CREDENTIALS_DRIFT            — dbt database connection profiles
//                                      (profiles.yml) containing target
//                                      credentials and connection parameters
//   HADOOP_ECOSYSTEM_DRIFT           — Apache Hadoop (HDFS/YARN), Hive, HBase,
//                                      and Flink security XML configurations
//   TRINO_PRESTO_DRIFT               — Trino / Presto query engine authentication
//                                      and TLS configuration properties
//   PIPELINE_ORCHESTRATION_DRIFT     — Dagster, Prefect, Kedro, and Argo
//                                      Workflows orchestration security configs
//   DATA_QUALITY_DRIFT               — Great Expectations, dbt tests, and
//                                      data catalog (DataHub, Apache Atlas)
//                                      access control configs
//   NOTEBOOK_SERVER_DRIFT            — Jupyter notebook and JupyterHub server
//                                      authentication and token configuration
//
// Design decisions:
//   • Path-segment and basename analysis only — no content reading.
//   • Vendor directory exclusion applied to all paths.
//   • Same penalty/cap scoring model as WS-60–79 for consistency.
//   • Dedup-per-rule: one finding per triggered rule (matchedPath + matchCount).
//   • airflow.cfg / spark-defaults.conf are globally unambiguous (tool-named).
//   • hdfs-site.xml / hive-site.xml / hbase-site.xml are globally unambiguous.
//   • flink-conf.yaml and dagster.yaml are globally unambiguous.
//   • profiles.yml is gated via isDbtProfilesFile (user contribution) because
//     the same filename appears in Jekyll, Ruby, and other tools.
//   • jupyter_notebook_config.py / jupyter_server_config.py are unambiguous.
//
// Exports:
//   isDbtProfilesFile       — user contribution point (see JSDoc below)
//   DATA_PIPELINE_RULES     — readonly rule registry
//   scanDataPipelineDrift   — main scanner, returns DataPipelineDriftResult

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DataPipelineRuleId =
  | 'AIRFLOW_SECURITY_DRIFT'
  | 'SPARK_SECURITY_DRIFT'
  | 'DBT_CREDENTIALS_DRIFT'
  | 'HADOOP_ECOSYSTEM_DRIFT'
  | 'TRINO_PRESTO_DRIFT'
  | 'PIPELINE_ORCHESTRATION_DRIFT'
  | 'DATA_QUALITY_DRIFT'
  | 'NOTEBOOK_SERVER_DRIFT'

export type DataPipelineSeverity = 'high' | 'medium' | 'low'
export type DataPipelineRiskLevel = 'none' | 'low' | 'medium' | 'high' | 'critical'

export type DataPipelineDriftFinding = {
  ruleId: DataPipelineRuleId
  severity: DataPipelineSeverity
  matchedPath: string
  matchCount: number
  description: string
  recommendation: string
}

export type DataPipelineDriftResult = {
  riskScore: number
  riskLevel: DataPipelineRiskLevel
  totalFindings: number
  highCount: number
  mediumCount: number
  lowCount: number
  findings: DataPipelineDriftFinding[]
  summary: string
}

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

const VENDOR_DIRS = [
  'node_modules/',
  'vendor/',
  '.git/',
  'dist/',
  'build/',
  '.next/',
  '.nuxt/',
  '__pycache__/',
  '.tox/',
  '.venv/',
  'venv/',
]

function isVendor(p: string): boolean {
  return VENDOR_DIRS.some((v) => p.includes(v))
}

// ---------------------------------------------------------------------------
// Directory sets used for gating ambiguous filenames
// ---------------------------------------------------------------------------

const AIRFLOW_DIRS  = ['airflow/', 'dags/', 'airflow-config/', '.airflow/', 'apache-airflow/']
const SPARK_DIRS    = ['spark/', 'spark-config/', 'conf/spark/', 'apache-spark/', 'spark/conf/']
const DBT_DIRS      = ['dbt/', '.dbt/', 'dbt-project/', 'transform/', 'transformations/dbt/']
const HADOOP_DIRS   = ['hadoop/', 'hdfs/', 'hadoop-config/', 'etc/hadoop/', 'conf/hadoop/']
const HIVE_DIRS     = ['hive/', 'hive-config/', 'etc/hive/', 'conf/hive/']
const HBASE_DIRS    = ['hbase/', 'hbase-config/', 'etc/hbase/', 'conf/hbase/']
const FLINK_DIRS    = ['flink/', 'flink-config/', 'conf/flink/', 'apache-flink/']
const TRINO_DIRS    = ['trino/', 'presto/', 'trino-config/', '.trino/', 'trinodb/']
const ORCHESTRATION_DIRS = [
  'dagster/', '.dagster/', 'dagster-config/',
  'prefect/', '.prefect/', 'prefect-config/',
  'kedro/', 'kedro-config/',
  'argo-workflows/', 'workflow-config/',
]
const DATA_QUALITY_DIRS = [
  'great_expectations/', 'great-expectations/', 'expectations/',
  'datacatalog/', 'datahub/', 'atlas/', 'openmetadata/',
]
const NOTEBOOK_DIRS = ['jupyter/', '.jupyter/', 'jupyterhub/', 'notebooks/']

function inAnyDir(pathLower: string, dirs: readonly string[]): boolean {
  return dirs.some((d) => pathLower.includes(d))
}

// ---------------------------------------------------------------------------
// Rule 1: AIRFLOW_SECURITY_DRIFT (high)
// Apache Airflow authentication, RBAC, and API security configuration
// ---------------------------------------------------------------------------

const AIRFLOW_UNGATED = new Set([
  'airflow.cfg',            // Main Airflow configuration — globally unambiguous
  'webserver_config.py',    // Flask AppBuilder auth config — Airflow-specific name
])

function isAirflowSecurityConfig(pathLower: string, base: string): boolean {
  if (AIRFLOW_UNGATED.has(base)) return true

  // airflow-*.cfg / airflow-*.yaml env-specific configs
  if (base.startsWith('airflow-') && (base.endsWith('.cfg') || base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) return true
  if (base.startsWith('airflow_') && (base.endsWith('.cfg') || base.endsWith('.py'))) return true

  if (!inAnyDir(pathLower, AIRFLOW_DIRS)) return false

  // Ambiguous filenames that are high-confidence inside Airflow directories
  if (
    base === 'secrets.yaml'     ||  // Airflow secrets backend config
    base === 'secrets.yml'      ||
    base === 'connections.yaml' ||  // Airflow connection definitions
    base === 'connections.json' ||
    base === 'variables.json'   ||  // Airflow Variables export
    base === 'variables.yaml'   ||
    base === 'config.cfg'       ||
    base === 'config.yaml'      ||
    base === 'config.yml'       ||
    base === '.env'             ||
    base === 'override.cfg'         // Override config for env-specific values
  ) return true

  // Any .cfg or .py in airflow directories
  if (base.endsWith('.cfg') || base.endsWith('.py')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 2: SPARK_SECURITY_DRIFT (high)
// Apache Spark encryption, authentication, and network security settings
// ---------------------------------------------------------------------------

const SPARK_UNGATED = new Set([
  'spark-defaults.conf',    // Primary Spark configuration — globally unambiguous
  'spark-env.sh',           // Spark environment variables — globally unambiguous
  'spark-env.sh.template',  // Template variant
])

function isSparkSecurityConfig(pathLower: string, base: string): boolean {
  if (SPARK_UNGATED.has(base)) return true

  // spark-*.conf / spark-*.sh prefix — file names its own tool
  if (base.startsWith('spark-') && (base.endsWith('.conf') || base.endsWith('.sh') || base.endsWith('.properties') || base.endsWith('.yaml'))) return true
  if (base.startsWith('spark_') && (base.endsWith('.conf') || base.endsWith('.properties'))) return true

  if (!inAnyDir(pathLower, SPARK_DIRS)) return false

  // Canonical Spark config files inside Spark directories
  if (
    base === 'spark.conf'         ||
    base === 'log4j.properties'   ||  // Logging/audit config for Spark
    base === 'log4j2.properties'  ||
    base === 'hive-site.xml'      ||  // Spark-Hive integration auth
    base === 'core-site.xml'      ||  // HDFS credentials for Spark
    base === 'metrics.properties' ||
    base === 'fairscheduler.xml'  ||
    base === 'workers'            ||  // Worker host list (affects cluster security)
    base === 'slaves'                 // Legacy worker host list
  ) return true

  // Any .conf, .properties, .xml, or .sh in Spark directories
  if (base.endsWith('.conf') || base.endsWith('.properties') || base.endsWith('.xml') || base.endsWith('.sh')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 3: DBT_CREDENTIALS_DRIFT (high)
// dbt database connection profiles and credential configurations
// ---------------------------------------------------------------------------

const DBT_UNGATED = new Set([
  'dbt_project.yml',    // dbt project manifest — globally unambiguous
  'dbt_project.yaml',   // YAML variant
  'dbt-project.yml',    // Hyphenated variant
])

/**
 * WS-80 user contribution — determines whether a file named `profiles.yml` (or
 * similar) is a dbt database credential profile rather than a profile config
 * for another tool (Jekyll, Ruby gems, etc.).
 *
 * The challenge: `profiles.yml` is dbt's canonical file for database connection
 * targets (containing host, user, password, schema, threads), but the same
 * filename is used by Jekyll for site profile configs and by some Ruby projects.
 *
 * Disambiguation approach — two independent signals raise confidence:
 *
 *   1. The file lives in a recognised dbt directory segment (`dbt/`, `.dbt/`,
 *      `transform/`, `transformations/`). These directory names only appear
 *      in data engineering projects, not in Jekyll or Ruby web projects.
 *
 *   2. The repo path contains a dbt-specific signal elsewhere: another path
 *      in the same commit changed `dbt_project.yml` / `dbt_project.yaml` —
 *      but we cannot check other files without content. Instead, check whether
 *      `dbt` appears as a directory segment anywhere in the path, indicating a
 *      dbt sub-project layout (`services/data/dbt/profiles.yml`).
 *
 *   3. The filename itself has a dbt-composite name: `profiles.yml` is the
 *      canonical form, but also accept `dbt-profiles.yml`, `dbt_profiles.yml`.
 *
 * An explicit `dbt_project.yml` or `dbt-project.yml` at root or project level
 * is always matched as ungated (handled in the main rule).
 *
 * @param pathLower  Lowercased, forward-slash-normalised file path.
 * @param base       Lowercased filename component of `pathLower`.
 */
export function isDbtProfilesFile(pathLower: string, base: string): boolean {
  // Explicit dbt prefix in filename — unambiguous regardless of location
  if (base === 'dbt-profiles.yml' || base === 'dbt_profiles.yml' || base === 'dbt-profiles.yaml') return true

  // profiles.yml must be in a dbt-signal directory to match
  if (base !== 'profiles.yml' && base !== 'profiles.yaml') return false

  // Signal 1: lives in a recognised dbt directory segment
  if (inAnyDir(pathLower, DBT_DIRS)) return true

  // Signal 2: 'dbt' appears as a path segment (not just a substring of a word)
  const segments = pathLower.split('/')
  if (segments.includes('dbt')) return true

  return false
}

function isDbtSecurityConfig(pathLower: string, base: string): boolean {
  if (DBT_UNGATED.has(base)) return true
  if (isDbtProfilesFile(pathLower, base)) return true

  // dbt-*.yml / dbt_*.yml prefix — file names its tool
  if (base.startsWith('dbt-') && (base.endsWith('.yml') || base.endsWith('.yaml') || base.endsWith('.json'))) return true
  if (base.startsWith('dbt_') && (base.endsWith('.yml') || base.endsWith('.yaml'))) return true

  if (!inAnyDir(pathLower, DBT_DIRS)) return false

  // Ambiguous filenames inside dbt directories
  if (
    base === 'packages.yml'     ||  // dbt package dependencies
    base === 'packages.yaml'    ||
    base === 'selectors.yml'    ||  // dbt node selectors
    base === 'sources.yml'      ||  // Data source declarations (credentials context)
    base === 'sources.yaml'     ||
    base === '.user.yml'        ||  // dbt user config (auth tokens, profile selection)
    base === 'dependencies.yml'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 4: HADOOP_ECOSYSTEM_DRIFT (high)
// Apache Hadoop, Hive, HBase, YARN, and Flink security configurations
// ---------------------------------------------------------------------------

const HADOOP_UNGATED = new Set([
  'hdfs-site.xml',       // HDFS configuration — globally unambiguous
  'core-site.xml',       // Hadoop core config (auth, FS) — globally unambiguous
  'yarn-site.xml',       // YARN resource manager config — globally unambiguous
  'mapred-site.xml',     // MapReduce config — globally unambiguous
  'hive-site.xml',       // Hive metastore + auth config — globally unambiguous
  'hbase-site.xml',      // HBase ZooKeeper + auth config — globally unambiguous
  'flink-conf.yaml',     // Flink cluster security config — globally unambiguous
  'ranger-admin-site.xml', // Apache Ranger authorization — globally unambiguous
  'ranger-hive-security.xml', // Ranger Hive plugin — globally unambiguous
  'kms-site.xml',        // Hadoop KMS key management service
])

function isHadoopEcosystemConfig(pathLower: string, base: string): boolean {
  if (HADOOP_UNGATED.has(base)) return true

  // Ranger/Hadoop security config prefix patterns
  if (base.startsWith('ranger-') && base.endsWith('.xml')) return true
  if (base.startsWith('hadoop-') && (base.endsWith('.xml') || base.endsWith('.conf'))) return true
  if (base.startsWith('flink-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.conf'))) return true

  // Flink configurations inside flink directories
  if (inAnyDir(pathLower, FLINK_DIRS)) {
    if (
      base === 'config.yaml'          ||
      base === 'log4j.properties'      ||
      base === 'log4j-console.properties' ||
      base === 'masters'               ||
      base === 'workers'               ||
      base === 'taskmanager.conf'
    ) return true
    if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.properties')) return true
  }

  // Hive configs in hive directories
  if (inAnyDir(pathLower, HIVE_DIRS)) {
    if (base.endsWith('.xml') || base === 'hive-env.sh' || base === 'hive-log4j2.properties') return true
  }

  // HBase configs in hbase directories
  if (inAnyDir(pathLower, HBASE_DIRS)) {
    if (base.endsWith('.xml') || base === 'hbase-env.sh') return true
  }

  // Hadoop configs in hadoop directories
  if (inAnyDir(pathLower, HADOOP_DIRS)) {
    if (base.endsWith('.xml') || base.endsWith('.conf') || base === 'hadoop-env.sh') return true
  }

  return false
}

// ---------------------------------------------------------------------------
// Rule 5: TRINO_PRESTO_DRIFT (medium)
// Trino / Presto query engine authentication and TLS configuration
// ---------------------------------------------------------------------------

const TRINO_UNGATED = new Set([
  'trino.properties',      // Trino client/server properties — unambiguous
  'presto.properties',     // Presto properties — unambiguous
  'trino-config.properties',
  'presto-config.properties',
])

function isTrinoPrestoConfig(pathLower: string, base: string): boolean {
  if (TRINO_UNGATED.has(base)) return true

  // trino-*.properties / presto-*.properties prefix
  if (base.startsWith('trino-') && (base.endsWith('.properties') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true
  if (base.startsWith('presto-') && (base.endsWith('.properties') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true

  if (!inAnyDir(pathLower, TRINO_DIRS)) return false

  // Ambiguous filenames inside Trino/Presto directories
  if (
    base === 'config.properties'    ||  // Trino server config (auth, TLS)
    base === 'jvm.config'           ||  // JVM args (memory, security manager)
    base === 'node.properties'      ||  // Node identity config
    base === 'log.properties'       ||  // Logging config
    base === 'access-control.properties' ||
    base === 'password-authenticator.properties' ||
    base === 'certificate.jks'      ||
    base === 'truststore.jks'
  ) return true

  // Any .properties or .yaml in trino/presto directories
  if (base.endsWith('.properties') || base.endsWith('.yaml') || base.endsWith('.yml')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 6: PIPELINE_ORCHESTRATION_DRIFT (medium)
// Dagster, Prefect, Kedro, and Argo Workflows security configurations
// ---------------------------------------------------------------------------

const ORCHESTRATION_UNGATED = new Set([
  'dagster.yaml',              // Dagster instance config — globally unambiguous
  'dagster.yml',
  'dagster_cloud.yaml',        // Dagster Cloud config — globally unambiguous
  'dagster_cloud.yml',
  'prefect.yaml',              // Prefect configuration — globally unambiguous
  'prefect.yml',
  'kedro.yml',                 // Kedro pipeline config — globally unambiguous
  'kedro.yaml',
])

function isPipelineOrchestrationConfig(pathLower: string, base: string): boolean {
  if (ORCHESTRATION_UNGATED.has(base)) return true

  // Tool-prefixed configs: dagster-*.yaml, prefect-*.yaml, kedro-*.yml
  if (base.startsWith('dagster-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) return true
  if (base.startsWith('dagster_') && (base.endsWith('.yaml') || base.endsWith('.yml'))) return true
  if (base.startsWith('prefect-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.toml'))) return true
  if (base.startsWith('kedro-') && (base.endsWith('.yaml') || base.endsWith('.yml'))) return true

  if (!inAnyDir(pathLower, ORCHESTRATION_DIRS)) return false

  // Ambiguous filenames inside orchestration directories
  if (
    base === 'config.yaml'      ||
    base === 'config.yml'       ||
    base === 'config.json'      ||
    base === 'workspace.yaml'   ||  // Dagster workspace (code locations)
    base === 'workspace.yml'    ||
    base === 'deployment.yaml'  ||  // Dagster Cloud deployment
    base === '.env'             ||
    base === 'values.yaml'      ||  // Helm chart for orchestrator
    base === 'secrets.yaml'
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 7: DATA_QUALITY_DRIFT (medium)
// Great Expectations, DataHub, Apache Atlas, and data catalog access configs
// ---------------------------------------------------------------------------

const DATA_QUALITY_UNGATED = new Set([
  'great_expectations.yml',    // Great Expectations project config — unambiguous
  'great_expectations.yaml',
  'great-expectations.yml',
  'datahub.yaml',              // DataHub ingestion config — unambiguous
  'datahub.yml',
  'atlas-application.properties', // Apache Atlas config — unambiguous
  'openmetadata.yaml',         // OpenMetadata config — unambiguous
])

function isDataQualityConfig(pathLower: string, base: string): boolean {
  if (DATA_QUALITY_UNGATED.has(base)) return true

  // Tool-prefixed configs: datahub-*.yaml, great-expectations-*.yml
  if (base.startsWith('datahub-') && (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.json'))) return true
  if (base.startsWith('great-expectations-') && (base.endsWith('.yml') || base.endsWith('.yaml'))) return true
  if (base.startsWith('atlas-') && (base.endsWith('.properties') || base.endsWith('.xml') || base.endsWith('.yaml'))) return true

  if (!inAnyDir(pathLower, DATA_QUALITY_DIRS)) return false

  // Ambiguous filenames inside data quality directories
  if (
    base === 'config.yml'          ||
    base === 'config.yaml'         ||
    base === 'config_variables.yml' ||  // GE datasource credentials
    base === 'config_variables.yaml' ||
    base === 'datasources.yml'     ||
    base === 'checkpoints.yml'     ||
    base === 'expectations.json'   ||
    base === 'ingestion.yaml'      ||  // DataHub ingestion pipeline
    base === 'ingestion.yml'
  ) return true

  // Any .yaml or .properties in data quality directories
  if (base.endsWith('.yaml') || base.endsWith('.yml') || base.endsWith('.properties')) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule 8: NOTEBOOK_SERVER_DRIFT (low)
// Jupyter notebook and JupyterHub server authentication and token configuration
// ---------------------------------------------------------------------------

const NOTEBOOK_UNGATED = new Set([
  'jupyter_notebook_config.py',   // Jupyter Notebook server config — unambiguous
  'jupyter_notebook_config.json', // JSON variant
  'jupyter_server_config.py',     // Jupyter Server config (new API) — unambiguous
  'jupyter_server_config.json',
  'jupyterhub_config.py',         // JupyterHub multi-user server config — unambiguous
  'jupyterhub_config.yaml',
])

function isNotebookServerConfig(pathLower: string, base: string): boolean {
  if (NOTEBOOK_UNGATED.has(base)) return true

  // jupyter-*.py / jupyterhub-*.py prefix variants
  if (base.startsWith('jupyter_') && (base.endsWith('.py') || base.endsWith('.json') || base.endsWith('.cfg'))) return true
  if (base.startsWith('jupyter-') && (base.endsWith('.py') || base.endsWith('.json') || base.endsWith('.cfg'))) return true
  if (base.startsWith('jupyterhub-') && (base.endsWith('.py') || base.endsWith('.yaml') || base.endsWith('.yml'))) return true
  if (base.startsWith('jupyterhub_') && (base.endsWith('.py') || base.endsWith('.yaml'))) return true

  if (!inAnyDir(pathLower, NOTEBOOK_DIRS)) return false

  // Ambiguous filenames inside Jupyter directories
  if (
    base === 'config.py'     ||
    base === 'config.yaml'   ||
    base === 'config.json'   ||
    base === '.env'          ||
    base === 'values.yaml'      // Helm values for JupyterHub deployment
  ) return true

  return false
}

// ---------------------------------------------------------------------------
// Rule registry
// ---------------------------------------------------------------------------

export const DATA_PIPELINE_RULES: ReadonlyArray<{
  id: DataPipelineRuleId
  severity: DataPipelineSeverity
  description: string
  recommendation: string
  match: (pathLower: string, base: string) => boolean
}> = [
  {
    id: 'AIRFLOW_SECURITY_DRIFT',
    severity: 'high',
    description: 'Apache Airflow authentication, RBAC, or API security configuration change detected.',
    recommendation:
      'Review webserver authentication backend changes (LDAP, OAuth, database), audit RBAC role and permission updates, verify Fernet key rotation (fernet_key config), and confirm the Airflow API authentication method has not been set to "deny_all" or left open.',
    match: isAirflowSecurityConfig,
  },
  {
    id: 'SPARK_SECURITY_DRIFT',
    severity: 'high',
    description: 'Apache Spark encryption or authentication configuration change detected.',
    recommendation:
      'Verify spark.authenticate and spark.network.crypto.enabled settings, audit RPC encryption changes (spark.io.encryption.enabled), review any PLAINTEXT listener additions in spark-defaults.conf, and confirm Spark History Server authentication has not been disabled.',
    match: isSparkSecurityConfig,
  },
  {
    id: 'DBT_CREDENTIALS_DRIFT',
    severity: 'high',
    description: 'dbt database connection profile or credential configuration change detected.',
    recommendation:
      'Ensure profiles.yml does not contain plaintext passwords (use environment variable references: "{{ env_var(\'DBT_DB_PASS\') }}"), audit target changes that point to production schemas, verify credential rotation is complete, and confirm the profile file is excluded from version control for sensitive deployments.',
    match: isDbtSecurityConfig,
  },
  {
    id: 'HADOOP_ECOSYSTEM_DRIFT',
    severity: 'high',
    description: 'Apache Hadoop, Hive, HBase, or Flink security configuration change detected.',
    recommendation:
      'Audit Kerberos principal and keytab changes in core-site.xml/hdfs-site.xml, review HDFS supergroup membership, verify Hive metastore authentication settings, confirm HBase ZooKeeper authentication configuration, and ensure Ranger authorization policies have not been weakened.',
    match: isHadoopEcosystemConfig,
  },
  {
    id: 'TRINO_PRESTO_DRIFT',
    severity: 'medium',
    description: 'Trino / Presto query engine authentication or TLS configuration change detected.',
    recommendation:
      'Verify the authenticator type in config.properties (PASSWORD or CERTIFICATE — never "allow-all"), audit catalog connection credential changes, review TLS keystore and truststore configuration, and confirm the http-server.http.enabled property is false in production.',
    match: isTrinoPrestoConfig,
  },
  {
    id: 'PIPELINE_ORCHESTRATION_DRIFT',
    severity: 'medium',
    description: 'Data pipeline orchestration (Dagster, Prefect, Kedro) security configuration change detected.',
    recommendation:
      'Audit code location and repository credential changes in Dagster workspace configs, review Prefect API key and workspace configuration, verify that orchestrator secrets backends (Vault, AWS Secrets Manager) are correctly configured, and confirm Helm values do not expose sensitive configuration in plaintext.',
    match: isPipelineOrchestrationConfig,
  },
  {
    id: 'DATA_QUALITY_DRIFT',
    severity: 'medium',
    description: 'Data quality or data catalog (Great Expectations, DataHub, Atlas) access configuration change detected.',
    recommendation:
      'Review datasource credential changes in config_variables.yml (ensure environment variable substitution, not plaintext), audit DataHub ingestion pipeline source credential updates, verify Apache Atlas / OpenMetadata authentication settings, and confirm expectation suite changes do not remove critical security data quality checks.',
    match: isDataQualityConfig,
  },
  {
    id: 'NOTEBOOK_SERVER_DRIFT',
    severity: 'low',
    description: 'Jupyter notebook or JupyterHub server authentication configuration change detected.',
    recommendation:
      'Ensure c.ServerApp.token and c.ServerApp.password are set and not empty strings, audit JupyterHub authenticator changes (PAM/OAuth), verify that notebook servers are not bound to 0.0.0.0 without authentication, and confirm SSL/TLS certificate configuration for production deployments.',
    match: isNotebookServerConfig,
  },
]

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

const SEVERITY_PENALTIES: Record<DataPipelineSeverity, { per: number; cap: number }> = {
  high:   { per: 15, cap: 45 },
  medium: { per: 8,  cap: 25 },
  low:    { per: 4,  cap: 15 },
}

function computeRiskScore(findings: DataPipelineDriftFinding[]): number {
  let score = 0
  for (const f of findings) {
    const { per, cap } = SEVERITY_PENALTIES[f.severity]
    score += Math.min(f.matchCount * per, cap)
  }
  return Math.min(score, 100)
}

function computeRiskLevel(score: number): DataPipelineRiskLevel {
  if (score === 0) return 'none'
  if (score < 20)  return 'low'
  if (score < 45)  return 'medium'
  if (score < 70)  return 'high'
  return 'critical'
}

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export function scanDataPipelineDrift(changedFiles: string[]): DataPipelineDriftResult {
  const normalise = (p: string) => p.replace(/\\/g, '/').toLowerCase()

  const findings: DataPipelineDriftFinding[] = []

  for (const rule of DATA_PIPELINE_RULES) {
    let firstPath  = ''
    let matchCount = 0

    for (const raw of changedFiles) {
      const p    = normalise(raw)
      const base = p.split('/').pop() ?? p

      if (isVendor(p)) continue
      if (!rule.match(p, base)) continue

      matchCount++
      if (!firstPath) firstPath = raw
    }

    if (matchCount > 0) {
      findings.push({
        ruleId:         rule.id,
        severity:       rule.severity,
        matchedPath:    firstPath,
        matchCount,
        description:    rule.description,
        recommendation: rule.recommendation,
      })
    }
  }

  // Sort: high → medium → low
  const ORDER: Record<DataPipelineSeverity, number> = { high: 0, medium: 1, low: 2 }
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])

  const riskScore   = computeRiskScore(findings)
  const riskLevel   = computeRiskLevel(riskScore)
  const highCount   = findings.filter((f) => f.severity === 'high').length
  const mediumCount = findings.filter((f) => f.severity === 'medium').length
  const lowCount    = findings.filter((f) => f.severity === 'low').length

  const summary =
    findings.length === 0
      ? 'No data pipeline or ETL security configuration changes detected.'
      : `${findings.length} data pipeline security rule${findings.length === 1 ? '' : 's'} triggered ` +
        `(${[
          highCount   ? `${highCount} high`    : '',
          mediumCount ? `${mediumCount} medium` : '',
          lowCount    ? `${lowCount} low`       : '',
        ].filter(Boolean).join(', ')}); risk score ${riskScore}/100.`

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
