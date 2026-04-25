import { describe, it, expect } from 'vitest'
import {
  scanDataPipelineDrift,
  isDbtProfilesFile,
  DATA_PIPELINE_RULES,
} from './dataPipelineDrift'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scan(files: string[]) {
  return scanDataPipelineDrift(files)
}

function ruleIds(files: string[]) {
  return scan(files).findings.map((f) => f.ruleId)
}

// ---------------------------------------------------------------------------
// Rule 1: AIRFLOW_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('AIRFLOW_SECURITY_DRIFT', () => {
  it('flags airflow.cfg (ungated)', () => {
    expect(ruleIds(['airflow.cfg'])).toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('flags webserver_config.py (ungated)', () => {
    expect(ruleIds(['webserver_config.py'])).toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('flags airflow-prod.cfg (prefix)', () => {
    expect(ruleIds(['airflow-prod.cfg'])).toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('flags airflow-staging.yaml (prefix)', () => {
    expect(ruleIds(['airflow-staging.yaml'])).toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('flags airflow_local.cfg (prefix)', () => {
    expect(ruleIds(['airflow_local.cfg'])).toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('flags secrets.yaml in airflow/ dir', () => {
    expect(ruleIds(['airflow/secrets.yaml'])).toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('flags connections.json in dags/ dir', () => {
    expect(ruleIds(['dags/connections.json'])).toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('flags variables.json in airflow/ dir', () => {
    expect(ruleIds(['airflow/variables.json'])).toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('flags any .py in airflow/ dir', () => {
    expect(ruleIds(['airflow/custom_auth.py'])).toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('flags any .cfg in airflow-config/ dir', () => {
    expect(ruleIds(['airflow-config/override.cfg'])).toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('does not flag config.yaml outside airflow dirs', () => {
    expect(ruleIds(['src/config.yaml'])).not.toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('does not flag random.py outside airflow dirs', () => {
    expect(ruleIds(['src/util.py'])).not.toContain('AIRFLOW_SECURITY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 2: SPARK_SECURITY_DRIFT
// ---------------------------------------------------------------------------

describe('SPARK_SECURITY_DRIFT', () => {
  it('flags spark-defaults.conf (ungated)', () => {
    expect(ruleIds(['spark-defaults.conf'])).toContain('SPARK_SECURITY_DRIFT')
  })
  it('flags spark-env.sh (ungated)', () => {
    expect(ruleIds(['spark-env.sh'])).toContain('SPARK_SECURITY_DRIFT')
  })
  it('flags spark-defaults-prod.conf (prefix)', () => {
    expect(ruleIds(['spark-defaults-prod.conf'])).toContain('SPARK_SECURITY_DRIFT')
  })
  it('flags spark-security.properties (prefix)', () => {
    expect(ruleIds(['spark-security.properties'])).toContain('SPARK_SECURITY_DRIFT')
  })
  it('flags log4j.properties in spark/ dir', () => {
    expect(ruleIds(['spark/conf/log4j.properties'])).toContain('SPARK_SECURITY_DRIFT')
  })
  it('flags hive-site.xml in spark/ dir', () => {
    expect(ruleIds(['spark/hive-site.xml'])).toContain('SPARK_SECURITY_DRIFT')
  })
  it('flags core-site.xml in spark-config/ dir', () => {
    expect(ruleIds(['spark-config/core-site.xml'])).toContain('SPARK_SECURITY_DRIFT')
  })
  it('flags any .sh in spark/conf/ dir', () => {
    expect(ruleIds(['spark/conf/bootstrap.sh'])).toContain('SPARK_SECURITY_DRIFT')
  })
  it('does not flag log4j.properties outside spark dirs', () => {
    expect(ruleIds(['src/log4j.properties'])).not.toContain('SPARK_SECURITY_DRIFT')
  })
  it('does not flag hive-site.xml outside spark/hadoop dirs when it is ungated', () => {
    // hive-site.xml IS ungated (it is in HADOOP_UNGATED), so it should match HADOOP rule
    expect(ruleIds(['hive-site.xml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
    expect(ruleIds(['hive-site.xml'])).not.toContain('SPARK_SECURITY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 3: DBT_CREDENTIALS_DRIFT (including isDbtProfilesFile)
// ---------------------------------------------------------------------------

describe('DBT_CREDENTIALS_DRIFT', () => {
  it('flags dbt_project.yml (ungated)', () => {
    expect(ruleIds(['dbt_project.yml'])).toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('flags dbt_project.yaml (ungated)', () => {
    expect(ruleIds(['dbt_project.yaml'])).toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('flags dbt-profiles.yml (explicit dbt prefix)', () => {
    expect(ruleIds(['dbt-profiles.yml'])).toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('flags dbt_profiles.yml (explicit dbt prefix)', () => {
    expect(ruleIds(['dbt_profiles.yml'])).toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('flags profiles.yml in dbt/ dir', () => {
    expect(ruleIds(['dbt/profiles.yml'])).toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('flags profiles.yml in .dbt/ dir', () => {
    expect(ruleIds(['.dbt/profiles.yml'])).toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('flags profiles.yml with dbt as path segment', () => {
    expect(ruleIds(['services/data/dbt/profiles.yml'])).toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('flags dbt-project.yml (prefix)', () => {
    expect(ruleIds(['dbt-project.yml'])).toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('flags packages.yml in dbt/ dir', () => {
    expect(ruleIds(['dbt/packages.yml'])).toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('flags sources.yml in transform/ dir', () => {
    expect(ruleIds(['transform/sources.yml'])).toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('does not flag profiles.yml outside dbt dirs', () => {
    // profiles.yml in a Jekyll project should NOT match
    expect(ruleIds(['_config.yml'])).not.toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('does not flag profiles.yml in generic src/', () => {
    expect(ruleIds(['src/profiles.yml'])).not.toContain('DBT_CREDENTIALS_DRIFT')
  })
  it('does not flag profiles.yml in ruby project without dbt context', () => {
    expect(ruleIds(['config/profiles.yml'])).not.toContain('DBT_CREDENTIALS_DRIFT')
  })
})

describe('isDbtProfilesFile', () => {
  it('returns true for profiles.yml in dbt/ dir', () => {
    expect(isDbtProfilesFile('dbt/profiles.yml', 'profiles.yml')).toBe(true)
  })
  it('returns true for profiles.yml with dbt as path segment', () => {
    expect(isDbtProfilesFile('services/data/dbt/profiles.yml', 'profiles.yml')).toBe(true)
  })
  it('returns true for dbt-profiles.yml anywhere', () => {
    expect(isDbtProfilesFile('config/dbt-profiles.yml', 'dbt-profiles.yml')).toBe(true)
  })
  it('returns false for profiles.yml in src/ without dbt context', () => {
    expect(isDbtProfilesFile('src/profiles.yml', 'profiles.yml')).toBe(false)
  })
  it('returns false for profiles.yml in ruby config/', () => {
    expect(isDbtProfilesFile('config/profiles.yml', 'profiles.yml')).toBe(false)
  })
  it('returns false for a random yaml named differently', () => {
    expect(isDbtProfilesFile('dbt/other.yaml', 'other.yaml')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// Rule 4: HADOOP_ECOSYSTEM_DRIFT
// ---------------------------------------------------------------------------

describe('HADOOP_ECOSYSTEM_DRIFT', () => {
  it('flags hdfs-site.xml (ungated)', () => {
    expect(ruleIds(['hdfs-site.xml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags core-site.xml (ungated)', () => {
    expect(ruleIds(['core-site.xml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags yarn-site.xml (ungated)', () => {
    expect(ruleIds(['yarn-site.xml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags hive-site.xml (ungated)', () => {
    expect(ruleIds(['hive-site.xml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags hbase-site.xml (ungated)', () => {
    expect(ruleIds(['hbase-site.xml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags flink-conf.yaml (ungated)', () => {
    expect(ruleIds(['flink-conf.yaml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags ranger-admin-site.xml (ungated)', () => {
    expect(ruleIds(['ranger-admin-site.xml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags kms-site.xml (ungated)', () => {
    expect(ruleIds(['kms-site.xml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags ranger-hive-security.xml (prefix)', () => {
    expect(ruleIds(['ranger-hive-security.xml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags flink-ssl.yaml (prefix)', () => {
    expect(ruleIds(['flink-ssl.yaml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags config.yaml in flink/ dir', () => {
    expect(ruleIds(['flink/config.yaml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags hive-env.sh in hive/ dir', () => {
    expect(ruleIds(['hive/hive-env.sh'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags hadoop-env.sh in hadoop/ dir', () => {
    expect(ruleIds(['hadoop/hadoop-env.sh'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('flags any .xml in hadoop-config/ dir', () => {
    expect(ruleIds(['hadoop-config/custom.xml'])).toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
  it('does not flag config.yaml outside hadoop/flink dirs', () => {
    expect(ruleIds(['src/config.yaml'])).not.toContain('HADOOP_ECOSYSTEM_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 5: TRINO_PRESTO_DRIFT
// ---------------------------------------------------------------------------

describe('TRINO_PRESTO_DRIFT', () => {
  it('flags trino.properties (ungated)', () => {
    expect(ruleIds(['trino.properties'])).toContain('TRINO_PRESTO_DRIFT')
  })
  it('flags presto.properties (ungated)', () => {
    expect(ruleIds(['presto.properties'])).toContain('TRINO_PRESTO_DRIFT')
  })
  it('flags trino-config.properties (ungated)', () => {
    expect(ruleIds(['trino-config.properties'])).toContain('TRINO_PRESTO_DRIFT')
  })
  it('flags trino-tls.properties (prefix)', () => {
    expect(ruleIds(['trino-tls.properties'])).toContain('TRINO_PRESTO_DRIFT')
  })
  it('flags presto-auth.yaml (prefix)', () => {
    expect(ruleIds(['presto-auth.yaml'])).toContain('TRINO_PRESTO_DRIFT')
  })
  it('flags config.properties in trino/ dir', () => {
    expect(ruleIds(['trino/config.properties'])).toContain('TRINO_PRESTO_DRIFT')
  })
  it('flags password-authenticator.properties in trino/ dir', () => {
    expect(ruleIds(['trino/password-authenticator.properties'])).toContain('TRINO_PRESTO_DRIFT')
  })
  it('flags jvm.config in presto/ dir', () => {
    expect(ruleIds(['presto/jvm.config'])).toContain('TRINO_PRESTO_DRIFT')
  })
  it('flags any .properties in trinodb/ dir', () => {
    expect(ruleIds(['trinodb/catalog/hive.properties'])).toContain('TRINO_PRESTO_DRIFT')
  })
  it('does not flag config.properties outside trino dirs', () => {
    expect(ruleIds(['src/config.properties'])).not.toContain('TRINO_PRESTO_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 6: PIPELINE_ORCHESTRATION_DRIFT
// ---------------------------------------------------------------------------

describe('PIPELINE_ORCHESTRATION_DRIFT', () => {
  it('flags dagster.yaml (ungated)', () => {
    expect(ruleIds(['dagster.yaml'])).toContain('PIPELINE_ORCHESTRATION_DRIFT')
  })
  it('flags dagster_cloud.yaml (ungated)', () => {
    expect(ruleIds(['dagster_cloud.yaml'])).toContain('PIPELINE_ORCHESTRATION_DRIFT')
  })
  it('flags prefect.yaml (ungated)', () => {
    expect(ruleIds(['prefect.yaml'])).toContain('PIPELINE_ORCHESTRATION_DRIFT')
  })
  it('flags kedro.yml (ungated)', () => {
    expect(ruleIds(['kedro.yml'])).toContain('PIPELINE_ORCHESTRATION_DRIFT')
  })
  it('flags dagster-prod.yaml (prefix)', () => {
    expect(ruleIds(['dagster-prod.yaml'])).toContain('PIPELINE_ORCHESTRATION_DRIFT')
  })
  it('flags dagster_cloud_staging.yaml (prefix)', () => {
    expect(ruleIds(['dagster_cloud_staging.yaml'])).toContain('PIPELINE_ORCHESTRATION_DRIFT')
  })
  it('flags prefect-cloud.yaml (prefix)', () => {
    expect(ruleIds(['prefect-cloud.yaml'])).toContain('PIPELINE_ORCHESTRATION_DRIFT')
  })
  it('flags workspace.yaml in dagster/ dir', () => {
    expect(ruleIds(['dagster/workspace.yaml'])).toContain('PIPELINE_ORCHESTRATION_DRIFT')
  })
  it('flags secrets.yaml in prefect/ dir', () => {
    expect(ruleIds(['prefect/secrets.yaml'])).toContain('PIPELINE_ORCHESTRATION_DRIFT')
  })
  it('flags values.yaml in argo-workflows/ dir', () => {
    expect(ruleIds(['argo-workflows/values.yaml'])).toContain('PIPELINE_ORCHESTRATION_DRIFT')
  })
  it('does not flag config.yaml outside orchestration dirs', () => {
    expect(ruleIds(['src/config.yaml'])).not.toContain('PIPELINE_ORCHESTRATION_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 7: DATA_QUALITY_DRIFT
// ---------------------------------------------------------------------------

describe('DATA_QUALITY_DRIFT', () => {
  it('flags great_expectations.yml (ungated)', () => {
    expect(ruleIds(['great_expectations.yml'])).toContain('DATA_QUALITY_DRIFT')
  })
  it('flags great_expectations.yaml (ungated)', () => {
    expect(ruleIds(['great_expectations.yaml'])).toContain('DATA_QUALITY_DRIFT')
  })
  it('flags datahub.yaml (ungated)', () => {
    expect(ruleIds(['datahub.yaml'])).toContain('DATA_QUALITY_DRIFT')
  })
  it('flags atlas-application.properties (ungated)', () => {
    expect(ruleIds(['atlas-application.properties'])).toContain('DATA_QUALITY_DRIFT')
  })
  it('flags openmetadata.yaml (ungated)', () => {
    expect(ruleIds(['openmetadata.yaml'])).toContain('DATA_QUALITY_DRIFT')
  })
  it('flags datahub-staging.yaml (prefix)', () => {
    expect(ruleIds(['datahub-staging.yaml'])).toContain('DATA_QUALITY_DRIFT')
  })
  it('flags atlas-env.properties (prefix)', () => {
    expect(ruleIds(['atlas-env.properties'])).toContain('DATA_QUALITY_DRIFT')
  })
  it('flags config_variables.yml in great_expectations/ dir', () => {
    expect(ruleIds(['great_expectations/config_variables.yml'])).toContain('DATA_QUALITY_DRIFT')
  })
  it('flags ingestion.yaml in datahub/ dir', () => {
    expect(ruleIds(['datahub/ingestion.yaml'])).toContain('DATA_QUALITY_DRIFT')
  })
  it('flags any .yaml in great-expectations/ dir', () => {
    expect(ruleIds(['great-expectations/datasources/postgres.yaml'])).toContain('DATA_QUALITY_DRIFT')
  })
  it('does not flag config.yaml outside data quality dirs', () => {
    expect(ruleIds(['src/config.yaml'])).not.toContain('DATA_QUALITY_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Rule 8: NOTEBOOK_SERVER_DRIFT
// ---------------------------------------------------------------------------

describe('NOTEBOOK_SERVER_DRIFT', () => {
  it('flags jupyter_notebook_config.py (ungated)', () => {
    expect(ruleIds(['jupyter_notebook_config.py'])).toContain('NOTEBOOK_SERVER_DRIFT')
  })
  it('flags jupyter_server_config.py (ungated)', () => {
    expect(ruleIds(['jupyter_server_config.py'])).toContain('NOTEBOOK_SERVER_DRIFT')
  })
  it('flags jupyterhub_config.py (ungated)', () => {
    expect(ruleIds(['jupyterhub_config.py'])).toContain('NOTEBOOK_SERVER_DRIFT')
  })
  it('flags jupyter_notebook_config.json (ungated)', () => {
    expect(ruleIds(['jupyter_notebook_config.json'])).toContain('NOTEBOOK_SERVER_DRIFT')
  })
  it('flags jupyterhub_config.yaml (ungated)', () => {
    expect(ruleIds(['jupyterhub_config.yaml'])).toContain('NOTEBOOK_SERVER_DRIFT')
  })
  it('flags jupyter_auth.py (prefix)', () => {
    expect(ruleIds(['jupyter_auth.py'])).toContain('NOTEBOOK_SERVER_DRIFT')
  })
  it('flags jupyterhub-config.py (prefix)', () => {
    expect(ruleIds(['jupyterhub-config.py'])).toContain('NOTEBOOK_SERVER_DRIFT')
  })
  it('flags values.yaml in jupyterhub/ dir', () => {
    expect(ruleIds(['jupyterhub/values.yaml'])).toContain('NOTEBOOK_SERVER_DRIFT')
  })
  it('flags config.py in jupyter/ dir', () => {
    expect(ruleIds(['jupyter/config.py'])).toContain('NOTEBOOK_SERVER_DRIFT')
  })
  it('does not flag config.py outside notebook dirs', () => {
    expect(ruleIds(['src/config.py'])).not.toContain('NOTEBOOK_SERVER_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Vendor exclusion
// ---------------------------------------------------------------------------

describe('vendor exclusion', () => {
  it('ignores airflow.cfg in vendor/', () => {
    expect(ruleIds(['vendor/airflow.cfg'])).toHaveLength(0)
  })
  it('ignores spark-defaults.conf in node_modules/', () => {
    expect(ruleIds(['node_modules/spark-defaults.conf'])).toHaveLength(0)
  })
  it('ignores hdfs-site.xml in __pycache__/', () => {
    expect(ruleIds(['__pycache__/hdfs-site.xml'])).toHaveLength(0)
  })
  it('ignores dagster.yaml in .venv/', () => {
    expect(ruleIds(['.venv/dagster.yaml'])).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Windows path normalisation
// ---------------------------------------------------------------------------

describe('Windows path normalisation', () => {
  it('normalises backslashes for airflow.cfg', () => {
    expect(ruleIds(['config\\airflow.cfg'])).toContain('AIRFLOW_SECURITY_DRIFT')
  })
  it('normalises backslashes for trino dir gating', () => {
    expect(ruleIds(['trino\\config.properties'])).toContain('TRINO_PRESTO_DRIFT')
  })
  it('normalises backslashes for dbt dir gating', () => {
    expect(ruleIds(['services\\dbt\\profiles.yml'])).toContain('DBT_CREDENTIALS_DRIFT')
  })
})

// ---------------------------------------------------------------------------
// Dedup — one finding per rule, multiple files increment matchCount
// ---------------------------------------------------------------------------

describe('dedup-per-rule', () => {
  it('produces one AIRFLOW_SECURITY_DRIFT finding for multiple airflow files', () => {
    const result = scan(['airflow.cfg', 'webserver_config.py', 'airflow/secrets.yaml'])
    const f = result.findings.find((x) => x.ruleId === 'AIRFLOW_SECURITY_DRIFT')
    expect(f).toBeDefined()
    expect(f!.matchCount).toBe(3)
  })
  it('produces one HADOOP_ECOSYSTEM_DRIFT finding for multiple hadoop files', () => {
    const result = scan(['hdfs-site.xml', 'core-site.xml', 'yarn-site.xml'])
    const f = result.findings.find((x) => x.ruleId === 'HADOOP_ECOSYSTEM_DRIFT')
    expect(f!.matchCount).toBe(3)
  })
  it('records firstPath correctly', () => {
    const result = scan(['hdfs-site.xml', 'core-site.xml'])
    const f = result.findings.find((x) => x.ruleId === 'HADOOP_ECOSYSTEM_DRIFT')
    expect(f!.matchedPath).toBe('hdfs-site.xml')
  })
})

// ---------------------------------------------------------------------------
// Dedup — cross-rule: non-colliding files trigger exactly one rule each
// ---------------------------------------------------------------------------

describe('cross-rule dedup', () => {
  it('airflow.cfg (AIRFLOW) and flink-conf.yaml (HADOOP) trigger distinct rules', () => {
    const result = scan(['airflow.cfg', 'flink-conf.yaml'])
    const ids = result.findings.map((f) => f.ruleId)
    expect(ids).toContain('AIRFLOW_SECURITY_DRIFT')
    expect(ids).toContain('HADOOP_ECOSYSTEM_DRIFT')
    const af = result.findings.find((f) => f.ruleId === 'AIRFLOW_SECURITY_DRIFT')!
    const hf = result.findings.find((f) => f.ruleId === 'HADOOP_ECOSYSTEM_DRIFT')!
    expect(af.matchCount).toBe(1)
    expect(hf.matchCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Scoring model
// ---------------------------------------------------------------------------

describe('scoring model', () => {
  it('HIGH×1 → score 15 → riskLevel low', () => {
    const r = scan(['airflow.cfg'])
    expect(r.riskScore).toBe(15)
    expect(r.riskLevel).toBe('low')
  })
  it('HIGH×3 → score 45 → riskLevel high (capped at 45)', () => {
    const r = scan(['airflow.cfg', 'webserver_config.py', 'airflow/secrets.yaml'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })
  it('MEDIUM×4 → score 25 → riskLevel medium (capped at 25)', () => {
    const r = scan([
      'trino/config.properties',
      'trino/jvm.config',
      'trino/node.properties',
      'trino/access-control.properties',
    ])
    expect(r.riskScore).toBe(25)
    expect(r.riskLevel).toBe('medium')
  })
  it('HIGH_cap(45)+MEDIUM_cap(25)=70 → riskLevel critical', () => {
    const r = scan([
      'airflow.cfg', 'webserver_config.py', 'airflow/secrets.yaml',        // AIRFLOW ×3 → cap 45
      'trino/config.properties', 'trino/jvm.config',
      'trino/node.properties', 'trino/access-control.properties',           // TRINO ×4 → cap 25
    ])
    expect(r.riskScore).toBe(70)
    expect(r.riskLevel).toBe('critical')
  })
  it('total clamped to 100 when all four HIGH rules fire at cap', () => {
    const r = scan([
      // AIRFLOW ×3 → 45
      'airflow.cfg', 'webserver_config.py', 'airflow-prod.cfg',
      // SPARK ×3 → 45
      'spark-defaults.conf', 'spark-env.sh', 'spark-security.properties',
      // DBT ×3 → 45
      'dbt_project.yml', 'dbt-profiles.yml', 'dbt/packages.yml',
      // HADOOP ×3 → 45
      'hdfs-site.xml', 'core-site.xml', 'hive-site.xml',
    ])
    expect(r.riskScore).toBe(100)
  })
  it('empty file list → score 0 → riskLevel none', () => {
    const r = scan([])
    expect(r.riskScore).toBe(0)
    expect(r.riskLevel).toBe('none')
  })
})

// ---------------------------------------------------------------------------
// Risk level boundaries
// ---------------------------------------------------------------------------

describe('risk level boundaries', () => {
  it('score 0 → none', () => expect(scan([]).riskLevel).toBe('none'))
  it('score 15 → low', () => expect(scan(['airflow.cfg']).riskLevel).toBe('low'))
  it('score 19 → low', () => {
    // HIGH(15) + LOW(4) = 19
    const r = scan(['airflow.cfg', 'jupyter_notebook_config.py'])
    expect(r.riskScore).toBe(19)
    expect(r.riskLevel).toBe('low')
  })
  it('score 23 → medium', () => {
    // HIGH(15) + MEDIUM(8) = 23
    const r = scan(['airflow.cfg', 'dagster.yaml'])
    expect(r.riskScore).toBe(23)
    expect(r.riskLevel).toBe('medium')
  })
  it('score 45 → high', () => {
    const r = scan(['airflow.cfg', 'webserver_config.py', 'airflow/secrets.yaml'])
    expect(r.riskScore).toBe(45)
    expect(r.riskLevel).toBe('high')
  })
  it('score 70 → critical', () => {
    const r = scan([
      'airflow.cfg', 'webserver_config.py', 'airflow/secrets.yaml',
      'trino/config.properties', 'trino/jvm.config', 'trino/node.properties', 'trino/access-control.properties',
    ])
    expect(r.riskScore).toBe(70)
    expect(r.riskLevel).toBe('critical')
  })
})

// ---------------------------------------------------------------------------
// Severity ordering: findings sorted high → medium → low
// ---------------------------------------------------------------------------

describe('severity ordering', () => {
  it('orders findings high → medium → low', () => {
    const r = scan(['airflow.cfg', 'dagster.yaml', 'jupyter_notebook_config.py'])
    const sevs = r.findings.map((f) => f.severity)
    expect(sevs[0]).toBe('high')
    const lastMedIdx = sevs.lastIndexOf('medium')
    const firstLowIdx = sevs.indexOf('low')
    if (lastMedIdx !== -1 && firstLowIdx !== -1) {
      expect(lastMedIdx).toBeLessThan(firstLowIdx)
    }
  })
})

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

describe('result shape', () => {
  it('returns correct counts for mixed severity findings', () => {
    const r = scan([
      'airflow.cfg', 'spark-defaults.conf',           // 2 HIGH
      'dagster.yaml', 'great_expectations.yml',        // 2 MEDIUM
      'jupyter_notebook_config.py',                    // 1 LOW
    ])
    expect(r.highCount).toBe(2)
    expect(r.mediumCount).toBe(2)
    expect(r.lowCount).toBe(1)
    expect(r.totalFindings).toBe(5)
  })
  it('summary includes rule count and risk score', () => {
    const r = scan(['airflow.cfg'])
    expect(r.summary).toContain('1 data pipeline security rule')
    expect(r.summary).toContain('15/100')
  })
  it('summary says none when no files match', () => {
    expect(scan([]).summary).toContain('No data pipeline')
  })
  it('each finding has all required fields', () => {
    const r = scan(['airflow.cfg'])
    const f = r.findings[0]!
    expect(f.ruleId).toBe('AIRFLOW_SECURITY_DRIFT')
    expect(f.severity).toBe('high')
    expect(f.matchedPath).toBe('airflow.cfg')
    expect(f.matchCount).toBe(1)
    expect(f.description.length).toBeGreaterThan(0)
    expect(f.recommendation.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// Multi-rule scenarios
// ---------------------------------------------------------------------------

describe('multi-rule scenarios', () => {
  it('single file triggering only one rule', () => {
    expect(ruleIds(['dagster.yaml'])).toEqual(['PIPELINE_ORCHESTRATION_DRIFT'])
  })
  it('entirely unrelated files produce no findings', () => {
    expect(ruleIds(['README.md', 'src/app.ts', 'package.json'])).toHaveLength(0)
  })
  it('all 8 rules can fire simultaneously', () => {
    const r = scan([
      'airflow.cfg',                  // AIRFLOW
      'spark-defaults.conf',          // SPARK
      'dbt_project.yml',              // DBT
      'hdfs-site.xml',                // HADOOP
      'trino.properties',             // TRINO
      'dagster.yaml',                 // ORCHESTRATION
      'great_expectations.yml',       // DATA_QUALITY
      'jupyter_notebook_config.py',   // NOTEBOOK
    ])
    expect(r.totalFindings).toBe(8)
    expect(r.highCount).toBe(4)
    expect(r.mediumCount).toBe(3)
    expect(r.lowCount).toBe(1)
  })
})

// ---------------------------------------------------------------------------
// Registry completeness
// ---------------------------------------------------------------------------

describe('registry completeness', () => {
  it('has exactly 8 rules', () => {
    expect(DATA_PIPELINE_RULES.length).toBe(8)
  })
  it('has 4 high-severity rules', () => {
    expect(DATA_PIPELINE_RULES.filter((r) => r.severity === 'high').length).toBe(4)
  })
  it('has 3 medium-severity rules', () => {
    expect(DATA_PIPELINE_RULES.filter((r) => r.severity === 'medium').length).toBe(3)
  })
  it('has 1 low-severity rule', () => {
    expect(DATA_PIPELINE_RULES.filter((r) => r.severity === 'low').length).toBe(1)
  })
  it('all rules have non-empty description and recommendation', () => {
    for (const rule of DATA_PIPELINE_RULES) {
      expect(rule.description.length).toBeGreaterThan(0)
      expect(rule.recommendation.length).toBeGreaterThan(0)
    }
  })
  it('all rule IDs are unique', () => {
    const ids = DATA_PIPELINE_RULES.map((r) => r.id)
    expect(new Set(ids).size).toBe(ids.length)
  })
})
