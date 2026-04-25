# Current Context

Reference docs:

- [sentinel-platform-spec.md](./sentinel-platform-spec.md)
- [IMPLEMENTATION_SPLIT.md](./IMPLEMENTATION_SPLIT.md)
- [PROJECT_TRACKER.md](./PROJECT_TRACKER.md)
- [TODO.md](./TODO.md)

This is the always-on context file for fast session recovery. Read this first at the start of every run, then keep it updated before ending the run.

## Current State

- Current phase: `Phase 0 - foundation implementation underway`
- Current milestone focus: `M0 -> M1`
- Current objective: build the runnable Sentinel control plane, carry the SBOM, breach-intel, semantic-fingerprint, and exploit-validation foundations into live integrations, and push the initialized Convex backend toward first real repository scan runs
- Canonical frontend/runtime stack: `TanStack Start + React + Tailwind + Bun`
- Canonical control-plane backend: `Convex`
- Planned analytics: `PostHog`
- Planned intelligence layer: `Python`
- Planned high-throughput edge and sandbox services: `Go`

## What Exists Right Now

- Root workspace scaffold with repository docs and service boundaries
- Runnable web app in `apps/web`
- Sentinel-styled dashboard and architecture view
- Convex control-plane schema for:
  - tenants
  - repositories
  - ingestion events
  - workflow runs and tasks
  - SBOM snapshots and components
  - breach disclosures
  - findings
  - gate decisions
- Seed mutation and sample event-ingestion mutation
- Reusable event-router templates for GitHub push and breach-disclosure workflows
- Workflow progress mutations with task-level state rollups back into workflow and event status
- Dashboard workflow progress view with staged task visibility and local simulation controls
- Python `sbom-ingest` worker with real repository parsing for `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `requirements.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`, `Dockerfile`, compose manifests, and Kubernetes-style image references
- Convex SBOM ingestion mutation scaffold for normalized inventory snapshots
- Bun bridge command in `apps/web` to run the Python SBOM worker and import snapshot payloads into Convex
- Dashboard repository inventory cards now surface latest SBOM snapshot metadata, source manifests, layer breakdowns, vulnerable inventory previews, and preview components
- Dashboard repository inventory cards now compare the latest snapshot against the previous import with added, removed, updated, and vulnerable-component delta summaries
- Breach-disclosure intake now matches the latest repository SBOM snapshot, flags vulnerable components, creates findings, and advances workflow state automatically
- Breach-disclosure normalization now includes GitHub Security Advisory and OSV adapter helpers with repo-aware package selection
- Breach matching is now version aware, distinguishing affected, unaffected, unknown, unmatched, and no-snapshot states instead of relying on name-only matches
- Live advisory ingest now includes Convex action entrypoints plus a Bun bridge command that fetch GitHub Security Advisories or OSV records by ID and route them through the existing disclosure workflow mutations
- GitHub webhook delivery is now wired in code through a Convex HTTP endpoint, signature-verifying internal action, and repository-aware push routing that feeds the existing workflow ingestion mutation path
- Scheduled and bulk advisory sync is now wired in code through repository-target queries, GitHub advisory list batching, OSV query-batch ingestion, a recurring Convex cron, and a Bun bridge command for manual sync runs
- The Breach Intel Aggregator MVP now persists advisory sync runs, captures skipped and failed sync outcomes per repository, and surfaces feed-health summaries plus recent sync activity in the dashboard
- Dashboard breach watchlist now shows per-repository match status, matched versions, and vulnerable inventory previews
- Semantic Fingerprinting MVP now creates path-aware candidate findings from changed-file metadata, carries push context into workflow events, and surfaces semantic candidate state in the dashboard
- Exploit Validation MVP now records local-first validation runs, classifies findings as validated, likely exploitable, or unexploitable, advances workflow validation stages, and surfaces recent validation evidence in the dashboard
- CI/CD Gate Enforcement MVP now evaluates findings against a configurable gate policy, writes per-finding gate decisions (approved/blocked/overridden), advances the policy workflow stage, surfaces enriched gate decision history in the dashboard, and supports manual override mutations with expiry
- PR Generation MVP now proposes fix branches from confirmed findings, generates typed PR proposals (version_bump / patch / manual), calls the GitHub API to create a branch + tracking commit + draft PR when GITHUB_TOKEN is configured, records the proposal state and PR URL back into the finding, and surfaces the prGeneration panel in the dashboard; the `simulate-github-push.mjs` script enables live webhook testing without a real GitHub repository webhook
- PR Generation file-modification capability now implemented: `proposeFix` fetches the repository's actual manifest file via the GitHub Contents API, applies a version-bump patch (requirements.txt → `==fixVersion` pin; pyproject.toml/Pipfile → `>=fixVersion` floor; package.json → preserves `^`/`~` prefix + bumps version), commits the real diff to the PR branch, and falls back transparently to the `.sentinel/fix-proposal.md` tracking placeholder when no manifest is found or the patch does not apply
- Python `agent-core` scaffold with a FastAPI health endpoint
- WS-12 API and dashboard v1 now has: `findings.list` / `findings.get` / `findings.stats` operator queries (filterable by status / severity / repositoryId, enriched with disclosure and PR context); `sbom.exportSnapshot` returning a full CycloneDX 1.5 BOM; `repositories.drilldown` returning SBOM summary, trust score aggregate, open findings, gate decisions, PR proposals, validation runs, and advisory sync health per repository; HTTP endpoints at `GET /api/sbom/export?snapshotId=<id>` (CycloneDX JSON download) and `GET /api/findings?tenantSlug=<slug>` (findings list); `convex/lib/cyclonedx.ts` pure BOM builder with PURL generation per ecosystem; `convex/lib/trustScore.ts` repositoryScore implemented as Strategy B (direct-weighted mean: 2×direct + 1×transitive / 3, with no-dep-aware fallbacks); HTTP endpoints now guarded by `requireApiKey` — reads `SENTINEL_API_KEY` from Convex env, fail-open in local dev, supports `X-Sentinel-Api-Key` and `Authorization: Bearer` headers
- WS-13 Prompt and supply-chain intelligence MVP now has: `convex/lib/promptInjection.ts` — 18-pattern heuristic scanner across role-escalation, system-prompt-leak, jailbreak, privilege-escalation, data-exfiltration, and encoding-obfuscation categories with cumulative 0–100 scoring and 4-tier risk levels; `convex/lib/supplyChainIntel.ts` — typosquat detection (bounded Levenshtein ≤2 edits against 100+ well-known package corpus across npm/pypi/cargo/go), suspicious-name detection, vulnerable-direct-dep flagging, untrusted-direct-dep flagging, high-blast-radius flagging, per-component and repository-level risk scores; `schema.ts` extended with `promptInjectionScans` table (indexed by tenant and repository); `convex/promptIntelligence.ts` — `scanContent` internal mutation (run scan + persist), `scanContentByRef` internal mutation (slug/provider-based adapter for action callers), `recentScans` public query (dashboard injection panel), `supplyChainAnalysis` public query (on-demand from latest SBOM snapshot)
- WS-13 Ingestion wiring complete: `convex/lib/githubWebhooks.ts` — extended `GithubPushPayload` with `head_commit.message` and per-commit `message` fields; new `collectCommitMessages` helper; `convex/githubWebhooks.ts` — `verifyAndRouteGithubWebhook` action now fire-and-forgets a `scanContentByRef` call on commit messages for every new (non-deduped) push event; `convex/breachIngest.ts` — `ingestGithubAdvisoriesForRepository` and `ingestOsvAdvisoriesForRepository` now fire-and-forget `scanContentByRef` calls on advisory summary+description text for every new advisory ingested; scan failures are logged and swallowed so they can never abort a sync batch
- WS-13 Dashboard panel complete: `dashboard.ts` — `repositories` array now includes `fullName`; `src/routes/index.tsx` — new `RepositoryIntelligencePanel` sub-component issues per-repository `recentScans` + `supplyChainAnalysis` queries and renders supply chain risk (overall score, flagged components, typosquat candidates) and injection scan history (risk level, score, category) inline in each repository card; tone helpers `injectionRiskTone` and `supplyChainRiskTone` map risk levels to StatusPill tones
- WS-95 Endpoint Security & EDR Configuration Drift Detector now complete: `convex/lib/endpointSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (CROWDSTRIKE_FALCON_DRIFT/SENTINELONE_POLICY_DRIFT/DEFENDER_ENDPOINT_DRIFT/EDR_EXCLUSION_LIST_DRIFT high; MDM_DEVICE_POLICY_DRIFT/CARBON_BLACK_SOPHOS_DRIFT/VULNERABILITY_SCANNER_DRIFT medium; TANIUM_ENDPOINT_MGMT_DRIFT low); CrowdStrike Falcon: falcon.cfg/falcon-sensor.cfg/falcon-agent.conf/cs.conf/crowdstrike.conf/falcon.conf/falcon-sensor.conf/falcon-prevention.json/crowdstrike-policy.json/crowdstrike-config.json ungated + crowdstrike-*/falcon-* prefix + CROWDSTRIKE_DIRS; SentinelOne: sentinelone.conf/sentinelone.json/s1.conf/s1-agent.conf/s1-policy.json/sentinelone-policy.json/sentinelone-config.json/sentinelone-agent.conf ungated + sentinelone-*/s1-* prefix + SENTINELONE_DIRS; Defender: mdatp-managed.json/mdatp.conf/mdatp-config.json/wdav-config.json/wdavcfg/defender-atp.json/defender-policy.json/mde-config.json/mdatp-managed.yaml/defender-for-endpoint.json ungated + mdatp-*/defender-*/mde-* prefix + DEFENDER_DIRS; EDR Exclusions (HIGH — adversary-targeted): edr-exclusions.json/av-exclusions.conf/defender-exclusions.json/edr-exclusions.yaml/av-exclusions.json/security-exclusions.json/exclusion-list.json/scan-exclusions.json/endpoint-exclusions.yaml/av-exclusions.yaml/edr-exclusions.yml/av-whitelist.conf/antivirus-exclusions.json/edr-whitelist.json ungated + edr-exclusion*/av-exclusion*/defender-exclusion* prefix + EXCLUSION_DIRS; `isMdmDevicePolicyFile` exported user contribution (.mobileconfig ungated globally unambiguous Apple MDM profile; jamf.conf/jamf.json/intune-policy.json/intune-compliance.json/sccm-config.xml ungated; enrollment.json/device-policy.json/compliance.json GATED on MDM_DIRS; jamf-*/intune-*/mdm-*/sccm-* prefix + MDM_DIRS); Carbon Black/Sophos: cbagent.cfg/cb.conf/cbrespond.conf/cbdaemon.conf/carbon_black.conf/carbon-black.conf/cbc.conf/sophos.conf/savdi.conf/sav-linux.conf/sep.conf/symantec-endpoint.conf ungated + carbonblack-*/cb-defense-*/sophos-*/symantec-* prefix + CBSOPHOS_DIRS; Vulnerability Scanner: nessus.conf/nessusd.conf/openvas.conf/gvm.conf/gvmd.conf/qualys-cloud-agent.conf/qualys-agent.conf/tenable-agent.conf/tenable.conf/rapid7-agent.conf/nexpose.conf ungated + nessus-*/openvas-*/qualys-*/tenable-*/rapid7-* prefix + VULNSCAN_DIRS; Tanium/BigFix: tanium.conf/tanium-client.conf/tanium-config.json/taniumclient.conf/bigfix.conf/bigfix-config.json/besclient.conf/besclient.cfg/manageengine.conf/me-agent.conf ungated + tanium-*/bigfix-*/manageengine-*/besclient-* prefix + TANIUM_DIRS; distinct from WS-67 (runtime security: Falco/OPA/Seccomp/AppArmor/fail2ban/auditd), WS-69 (developer security tooling: SAST/SCA/secret scanning), WS-74 (mobile app security), WS-83 (config management), WS-89 (OS hardening: sshd_config/sudoers/sysctl/PAM); max score 73 = 'high'; score 15 = 'medium'; 211 tests (1 test fix: dedup-per-rule correction); `endpointSecurityDriftResults` schema table (2 indexes); `convex/endpointSecurityDriftIntel.ts` (6 entrypoints: recordEndpointSecurityDriftScan/triggerEndpointSecurityDriftScan/getLatestEndpointSecurityDriftScan/getLatestEndpointSecurityDriftBySlug/getEndpointSecurityDriftScanHistory/getEndpointSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-94; `GET /api/repository/endpoint-security-drift` HTTP route; `api.d.ts` registration; `RepositoryEndpointSecurityDriftPanel` dashboard component (rule labels: CROWDSTRIKE_FALCON_DRIFT→"CrowdStrike Falcon"/SENTINELONE_POLICY_DRIFT→"SentinelOne"/DEFENDER_ENDPOINT_DRIFT→"Microsoft Defender / MDE"/EDR_EXCLUSION_LIST_DRIFT→"EDR / AV Exclusion List"/MDM_DEVICE_POLICY_DRIFT→"MDM / Jamf / Intune"/CARBON_BLACK_SOPHOS_DRIFT→"Carbon Black / Sophos"/VULNERABILITY_SCANNER_DRIFT→"Vulnerability Scanner"/TANIUM_ENDPOINT_MGMT_DRIFT→"Tanium / BigFix"). All checks green (8065/8065 tests, 118 files).
- WS-94 Network Monitoring & SNMP Security Configuration Drift Detector now complete: `convex/lib/networkMonitoringDrift.ts` — pure library, 8 rules across 3 severity tiers (SNMPD_DAEMON_DRIFT/NAGIOS_NRPE_DRIFT/ZABBIX_MONITORING_DRIFT/NETFLOW_ANALYSIS_DRIFT high; LIBRENMS_OXIDIZED_DRIFT/NETDATA_STREAMING_DRIFT/SNMP_TRAP_RECEIVER_DRIFT medium; NETWORK_PROBE_CONFIG_DRIFT low); SNMP daemon: snmpd.conf/snmp.conf/snmpd-v3.conf/snmpd.conf.local ungated + community.conf/users.conf/access.conf GATED in SNMP_DIRS + snmpd-*/snmp-config-* prefix + SNMPD_DIRS; Nagios/NRPE: nagios.cfg/nrpe.cfg/nrpe.conf/nrpe_local.cfg/icinga.cfg/icinga2.conf ungated + objects.cfg/hosts.cfg/services.cfg GATED in NAGIOS_DIRS + nagios-*/nrpe-*/icinga-* prefix; Zabbix: zabbix_server.conf/zabbix_agentd.conf/zabbix_proxy.conf/zabbix_agent2.conf ungated + zabbix-*/zabbix_* prefix + ZABBIX_DIRS; NetFlow: pmacct.conf/nfdump.conf/ntopng.conf/nprobe.conf/softflowd.conf/fastnetmon.conf ungated + pmacct-*/ntopng-*/netflow-*/sflow-* prefix + NETFLOW_DIRS; `isNetworkNmsConfig` exported user contribution (oxidized.conf ungated; config.php GATED on librenms//cacti//observium/ dir; librenms-*/oxidized-*/cacti-*/rancid-* prefix; NMS_DIRS membership); Netdata: netdata.conf/health_alarm_notify.conf/exporting.conf ungated + stream.conf/health.conf GATED in NETDATA_DIRS + netdata-*/health-* prefix; SNMP trap: snmptrapd.conf/snmptt.conf/snmptt.ini/trapd.conf ungated + snmptrapd-*/snmptt-*/trap-* prefix + TRAP_DIRS; Network probe: masscan.conf/masscan.json/zmap.conf/nmap.conf ungated + masscan-*/zmap-* prefix + PROBE_DIRS; distinct from WS-71 (Prometheus/Alertmanager/Grafana/OTel observability), WS-86 (Splunk/Elastic SIEM/security analytics), WS-88 (BIND/Unbound/CoreDNS DNS server security), WS-68 (iptables/nftables/UFW/firewalld perimeter); max score 73 = 'high'; score 15 = 'medium'; 183 tests (fixed 3 tests: .d suffix and .db extension not in allowlists); `networkMonitoringDriftResults` schema table (2 indexes); `convex/networkMonitoringDriftIntel.ts` (6 entrypoints: recordNetworkMonitoringDriftScan/triggerNetworkMonitoringDriftScan/getLatestNetworkMonitoringDriftScan/getLatestNetworkMonitoringDriftBySlug/getNetworkMonitoringDriftScanHistory/getNetworkMonitoringDriftSummaryByTenant); fire-and-forget in events.ts before WS-93; `GET /api/repository/network-monitoring-drift` HTTP route; `api.d.ts` registration; `RepositoryNetworkMonitoringDriftPanel` dashboard component (rule labels: SNMPD_DAEMON_DRIFT→"SNMP Daemon"/NAGIOS_NRPE_DRIFT→"Nagios / NRPE / Icinga"/ZABBIX_MONITORING_DRIFT→"Zabbix"/NETFLOW_ANALYSIS_DRIFT→"NetFlow / sFlow / ntopng"/LIBRENMS_OXIDIZED_DRIFT→"LibreNMS / Oxidized / NMS"/NETDATA_STREAMING_DRIFT→"Netdata Streaming"/SNMP_TRAP_RECEIVER_DRIFT→"SNMP Trap Receiver"/NETWORK_PROBE_CONFIG_DRIFT→"Network Probe / Scanner"). All checks green (7854/7854 tests, 117 files).
- WS-93 VoIP & Unified Communications Security Configuration Drift Detector now complete: `convex/lib/voipSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (ASTERISK_PBX_DRIFT/KAMAILIO_OPENSIPS_DRIFT/FREESWITCH_DRIFT/SIP_TRUNK_CREDENTIALS_DRIFT high; JITSI_WEBRTC_DRIFT/VOIP_GATEWAY_DRIFT/WEBCONFERENCE_SECURITY_DRIFT medium; VOIP_CDR_MONITORING_DRIFT low); Asterisk: sip.conf/pjsip.conf/asterisk.conf/extensions.conf/voicemail.conf/queues.conf/iax.conf ungated + manager.conf/rtp.conf/cdr.conf GATED in ASTERISK_DIRS + asterisk-*/freepbx-* prefix + ASTERISK_DIRS dir membership; Kamailio: kamailio.cfg/opensips.cfg/opensips.conf/kamailio-local.cfg ungated + kamailio-*/opensips-* prefix + KAMAILIO_DIRS; FreeSWITCH: freeswitch.xml/switch.conf.xml/freeswitch.yaml ungated + vars.xml/dialplan.xml/directory.xml/sofia.conf.xml/event_socket.conf.xml GATED in FREESWITCH_DIRS + freeswitch-*/fs-* prefix; SIP Trunk: sip-trunk.conf/sip-provider.conf/sip-credentials.conf/voip-credentials.conf/trunk-config.conf ungated + trunk.conf/provider.conf GATED in SIP_TRUNK_DIRS + sip-trunk-*/sip-provider-*/voip-credentials-* prefix; Jitsi: coturn.conf/turnserver.conf/jitsi-meet.conf/jicofo.conf/jvb.conf/prosody.cfg.lua ungated + jitsi-*/coturn-*/turn-*/webrtc-* prefix + JITSI_DIRS; VoIP Gateway: voip-gateway.conf/sip-gateway.conf/ata-config.conf ungated + sangoma-*/audiocodes-*/patton-*/grandstream-*/ata-* prefix + VOIP_GATEWAY_DIRS; `isWebConferenceServerConfig` exported user contribution (synapse.yaml/rocketchat.conf/bigbluebutton.properties/mattermost.json ungated; homeserver.yaml ONLY gated on matrix/ or synapse/ dir; synapse-*/matrix-*/bbb-*/mattermost-*/rocketchat-*/nextcloud-talk-* prefix; WEBCONF_DIRS dir membership); CDR: homer.cfg/sngrep.conf/heplify.yml/heplify-server.yaml/sipcapture.conf ungated + homer-*/sngrep-*/heplify-*/voip-cdr-* prefix + CDR_DIRS; distinct from WS-70 (LDAP/PAM/Vault), WS-68 (iptables/nftables), WS-66 (certificate PKI), WS-78 (MQTT/RabbitMQ); max score 73 = 'high'; score 15 = 'medium'; 244 tests all passing; `voipSecurityDriftResults` schema table (2 indexes); `convex/voipSecurityDriftIntel.ts` (6 entrypoints: recordVoipSecurityDriftScan/triggerVoipSecurityDriftScan/getLatestVoipSecurityDriftScan/getLatestVoipSecurityDriftBySlug/getVoipSecurityDriftScanHistory/getVoipSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-92; `GET /api/repository/voip-security-drift` HTTP route; `api.d.ts` registration; `RepositoryVoipSecurityDriftPanel` dashboard component (rule labels: ASTERISK_PBX_DRIFT→"Asterisk / FreePBX"/KAMAILIO_OPENSIPS_DRIFT→"Kamailio / OpenSIPS"/FREESWITCH_DRIFT→"FreeSWITCH"/SIP_TRUNK_CREDENTIALS_DRIFT→"SIP Trunk Credentials"/JITSI_WEBRTC_DRIFT→"Jitsi / TURN / WebRTC"/VOIP_GATEWAY_DRIFT→"VoIP Gateway"/WEBCONFERENCE_SECURITY_DRIFT→"Web Conferencing Server"/VOIP_CDR_MONITORING_DRIFT→"VoIP CDR / Monitoring"). All checks green (7671/7671 tests, 116 files).
- WS-92 Virtualization & Hypervisor Security Configuration Drift Detector now complete: `convex/lib/virtualizationSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (VSPHERE_ESXI_SECURITY_DRIFT/LIBVIRT_KVM_SECURITY_DRIFT/DOCKER_DAEMON_CONFIG_DRIFT/PROXMOX_CLUSTER_SECURITY_DRIFT high; XEN_XENSERVER_DRIFT/HYPERV_SECURITY_DRIFT/VM_CONSOLE_ACCESS_DRIFT medium; VIRTUAL_SWITCH_SDN_DRIFT low); VMware vSphere: vmware.conf/vsphere.conf/vcenter.conf/esxi.conf/vpxa.cfg/vpxd.cfg/vsphere-ha.cfg/vcsa.conf ungated + vsphere-*/vcenter-*/vmware-*/esxi-* prefix + VSPHERE_DIRS membership; KVM/libvirt: libvirtd.conf/libvirt.conf/virtlogd.conf/virtnodedevd.conf/virtqemud.conf ungated + qemu.conf/networks.xml/storage.xml GATED in LIBVIRT_DIRS + libvirt-*/kvm-*/qemu-*/virt-* prefix; Docker daemon: docker-daemon.json/docker-daemon.yaml/containerd-config.toml ungated + daemon.json/config.toml/config.json GATED in DOCKER_DAEMON_DIRS + docker-config-*/containerd-*/dockerd-* prefix; Proxmox: datacenter.cfg/pve.conf/proxmox.conf/ha-manager.cfg ungated + corosync.conf/storage.cfg/users.cfg GATED in PROXMOX_DIRS + proxmox-*/pve-* prefix; Xen: xend.conf/xl.conf/xen.conf/xapi.conf ungated + xen-*/xenserver-*/xcp-* prefix + XEN_DIRS; Hyper-V: hyperv-config.xml/hyper-v-config.xml/hyperv-settings.xml/hyperv.conf ungated + hyperv-*/hyper-v-* prefix + HYPERV_DIRS; `isVmConsoleAccessConfig` exported user contribution (spice-vdagent.conf/virt-manager.conf ungated exact; spice-*/vnc-* prefix ungated; spice.conf/vnc.conf/console.conf/rdp.conf GATED on VM_CONSOLE_DIRS); OVS/SDN: ovs-vswitchd.conf/ovsdb.conf/openvswitch.conf/nsx-manager.conf/ovs-config.yaml ungated + ovs-*/openvswitch-*/nsx-*/sdn-* prefix + SDN_DIRS; distinct from WS-63 (Dockerfile/k8s RBAC/container runtime AppArmor-seccomp), WS-68 (host-level iptables/nftables), WS-85 (backup agents), WS-87 (NFS/SMB), WS-72 (service mesh); max score 73 = 'high'; 123 tests all passing; `virtualizationSecurityDriftResults` schema table (2 indexes); `convex/virtualizationSecurityDriftIntel.ts` (6 entrypoints: recordVirtualizationSecurityDriftScan/triggerVirtualizationSecurityDriftScan/getLatestVirtualizationSecurityDriftScan/getLatestVirtualizationSecurityDriftBySlug/getVirtualizationSecurityDriftScanHistory/getVirtualizationSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-91; `GET /api/repository/virtualization-security-drift` HTTP route; `api.d.ts` registration; `RepositoryVirtualizationSecurityDriftPanel` dashboard component (rule labels: VSPHERE_ESXI_SECURITY_DRIFT→"VMware vSphere / ESXi"/LIBVIRT_KVM_SECURITY_DRIFT→"KVM / libvirt"/DOCKER_DAEMON_CONFIG_DRIFT→"Docker Daemon / containerd"/PROXMOX_CLUSTER_SECURITY_DRIFT→"Proxmox VE Cluster"/XEN_XENSERVER_DRIFT→"Xen / XenServer"/HYPERV_SECURITY_DRIFT→"Hyper-V"/VM_CONSOLE_ACCESS_DRIFT→"VM Console Access"/VIRTUAL_SWITCH_SDN_DRIFT→"Open vSwitch / SDN"). All checks green (7427/7427 tests, 115 files).
- WS-91 IoT & Embedded Device Security Configuration Drift Detector now complete: `convex/lib/iotEmbeddedSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (BALENA_IOT_FLEET_DRIFT/GREENGRASS_IOT_DRIFT/FIRMWARE_SIGNING_DRIFT/MENDER_OTA_DRIFT high; ZIGBEE_ZWAVE_CONTROLLER_DRIFT/AZURE_IOT_HUB_DRIFT/DEVICE_MANAGEMENT_DRIFT medium; IOT_NETWORK_GATEWAY_DRIFT low); Balena: balena.yml/balena.yaml/balena.json/balena-compose.yml/balena-compose.yaml ungated + balena-* prefix + BALENA_DIRS membership; Greengrass: greengrass-config.json/gg-config.json/gg-group-config.json/greengrass-config.yaml/iot-policy.json ungated + greengrass*.json/iot-policy-*.json prefix + GREENGRASS gated exact (config.json/deployments.json/subscriptions.json/connectivity.json/resources.json/deployment.json) in GREENGRASS_DIRS; Firmware: signing_config.json/signing_config.yaml/mcuboot.config.yaml/mcuboot.config.yml/mcuboot.config.json/mflt.conf/esptool.cfg/fwsign.conf/imgtool-signing.conf/imgtool-signing.yaml/imgtool-signing.yml/bootloader-keys.json ungated + firmware-*.conf/signing-*.yaml/mcuboot*.yaml/secure-boot*.conf prefix + FIRMWARE_DIRS membership; Mender: mender.conf/mender-artifact.conf/artifact_info/mender-update.conf/mender-identity.conf/mender-connect.conf ungated + mender-*.yaml/mender*.conf prefix + MENDER_DIRS membership; `isZigbeeControllerConfig` exported user contribution (configuration.yaml/yml in ZIGBEE_DIRS; settings.json in ZIGBEE_DIRS; zwavejs* prefix; coordinator_backup.json/database.db in ZIGBEE_DIRS; zigbee*/zwave* prefix ungated); Azure IoT: iothub-connection.json/dps-config.json/device-provisioning.json/azure-iot.json/azure-iot-hub.json/iotedge-config.yaml/iotedge-config.yml/config.toml ungated + azure-iot*.yaml/iot-hub-*.json/dps-*.json/iotedge*.toml prefix + AZURE_IOT gated exact (deployment.json/deployment.template.json/desired-properties.json/config.yaml) in AZURE_IOT_DIRS; Device Mgmt: thingsboard.yml/yaml/json/hawkbit.yml/yaml/json/edgex-configuration.toml/pelion-config.json/yaml ungated + thingsboard-*/hawkbit-*/edgex-*/pelion-* prefix + DEVICE_MGMT_DIRS membership; LoRaWAN: chirpstack.toml/chirpstack-gateway-bridge.toml/chirpstack-gateway-os.toml/chirpstack-application-server.toml/the-things-stack.yml/the-things-stack.yaml/tts-stack.yml/lorawan-server.toml/lorawan-server.yaml ungated + chirpstack-*/lorawan-*/ttn-* prefix + LORAWAN_DIRS membership; distinct from WS-63 (k8s RBAC), WS-62 (cloud IAM), WS-78 (MQTT mosquitto.conf), WS-84 (VPN), WS-89 (sshd_config/sudoers), WS-90 (wireless/RADIUS hostapd); max score 73 = 'high'; score 15 = 'medium' (15 is not < 15); 133 tests all passing; `iotEmbeddedSecurityDriftResults` schema table (2 indexes); `convex/iotEmbeddedSecurityDriftIntel.ts` (6 entrypoints: recordIotEmbeddedSecurityDriftScan/triggerIotEmbeddedSecurityDriftScan/getLatestIotEmbeddedSecurityDriftScan/getLatestIotEmbeddedSecurityDriftBySlug/getIotEmbeddedSecurityDriftScanHistory/getIotEmbeddedSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-90; `GET /api/repository/iot-embedded-security-drift` HTTP route; `api.d.ts` registration; `RepositoryIotEmbeddedSecurityDriftPanel` dashboard component (rule labels: BALENA_IOT_FLEET_DRIFT→"Balena IoT Fleet"/GREENGRASS_IOT_DRIFT→"AWS IoT / Greengrass"/FIRMWARE_SIGNING_DRIFT→"Firmware Signing / OTA"/MENDER_OTA_DRIFT→"Mender OTA"/ZIGBEE_ZWAVE_CONTROLLER_DRIFT→"Zigbee / Z-Wave Controller"/AZURE_IOT_HUB_DRIFT→"Azure IoT Hub / DPS"/DEVICE_MANAGEMENT_DRIFT→"IoT Device Management"/IOT_NETWORK_GATEWAY_DRIFT→"LoRaWAN / Network Gateway"). All checks green (7304/7304 tests, 114 files).
- WS-90 Wireless Network & RADIUS Authentication Security Configuration Drift Detector now complete: `convex/lib/wirelessRadiusDrift.ts` — pure library, 8 rules across 3 severity tiers (HOSTAPD_AP_CONFIG_DRIFT/WPA_SUPPLICANT_DRIFT/FREERADIUS_SERVER_DRIFT/TACACS_PLUS_DRIFT high; WIRELESS_CONTROLLER_DRIFT/RADIUS_POLICY_DRIFT/DOT1X_EAP_PROFILE_DRIFT medium; CAPTIVE_PORTAL_DRIFT low); hostapd.conf/hostapd.wpa_psk/hostapd.eap_user/hostapd.accept/hostapd.deny ungated; wpa_supplicant.conf ungated; wpa_supplicant-*.conf interface-specific per-interface variants; radiusd.conf/freeradius.conf ungated; clients.conf/users/huntgroups/dictionary gated on RADIUS_DIRS; tac_plus.conf/tac_plus.cfg/tacacs.conf/tacacs+.conf ungated; `isWirelessControllerConfig` exported user contribution (config.gateway.json/config.system.json/config.properties in WC_DIRS; any .json/.yaml/.cfg/.conf in WC_DIRS; wlc-*/aruba-*/unifi-* prefix); RADIUS policy: gated on RADIUS_DIRS + sites-enabled//sites-available//policy.d//mods-enabled//mods-available/ path segments + proxy.conf/policy.conf/filter.conf/sql.conf exact names; 802.1X: eapol.conf/eapol_test.conf ungated; eap-*/eap_* prefix; eap.conf gated on radius or hostapd dirs; DOT1X_DIRS membership; captive portal: nodogsplash.conf/chillispot.conf/chilli.conf/coova-chilli.conf ungated; captive-portal-*/nodogsplash-* prefix; PORTAL_DIRS membership; distinct from WS-78 (MQTT broker mosquitto.conf), WS-70 (LDAP/Vault/PAM), WS-84 (VPN tunnels), WS-89 (sshd_config/sudoers); max score 73 = 'high'; 126 tests all passing; `wirelessRadiusDriftResults` schema table (2 indexes); `convex/wirelessRadiusDriftIntel.ts` (6 entrypoints: recordWirelessRadiusDriftScan/triggerWirelessRadiusDriftScan/getLatestWirelessRadiusDriftScan/getLatestWirelessRadiusDriftBySlug/getWirelessRadiusDriftScanHistory/getWirelessRadiusDriftSummaryByTenant); fire-and-forget in events.ts before WS-89; `GET /api/repository/wireless-radius-drift` HTTP route; `api.d.ts` registration; `RepositoryWirelessRadiusDriftPanel` dashboard component (rule labels: HOSTAPD_AP_CONFIG_DRIFT→"Wi-Fi AP (hostapd)"/WPA_SUPPLICANT_DRIFT→"WPA Supplicant"/FREERADIUS_SERVER_DRIFT→"FreeRADIUS Server"/TACACS_PLUS_DRIFT→"TACACS+"/WIRELESS_CONTROLLER_DRIFT→"Wireless Controller"/RADIUS_POLICY_DRIFT→"RADIUS Policy"/DOT1X_EAP_PROFILE_DRIFT→"802.1X / EAP Profile"/CAPTIVE_PORTAL_DRIFT→"Captive Portal"). All checks green (7171/7171 tests, 113 files).
- WS-89 Operating System Security Hardening Configuration Drift Detector now complete: `convex/lib/osSecurityHardeningDrift.ts` — pure library, 8 rules across 3 severity tiers (SYSCTL_KERNEL_HARDENING_DRIFT/SSH_SERVER_CONFIG_DRIFT/SUDOERS_PRIVILEGE_DRIFT/GRUB_BOOTLOADER_SECURITY_DRIFT high; SELINUX_POLICY_DRIFT/OS_ACCESS_CONTROL_DRIFT/NTP_TIMESYNC_SECURITY_DRIFT medium; OS_LOGIN_BANNER_DRIFT low); sysctl.conf ungated; sshd_config/ssh_config ungated; sudoers/sudoers.tmp ungated; grub.cfg/grub.conf/grub2.cfg/grubenv/user.cfg ungated; /etc/default/grub: base='grub' AND path contains 'default/'; semanage.conf/selinux.conf ungated; /etc/selinux/config: base='config' AND path contains 'selinux'; hosts.allow/hosts.deny/at.allow/at.deny/cron.allow/cron.deny/securetty/nologin/ftpusers ungated; ntp.conf/ntpd.conf/chrony.conf/chronyd.conf/timesyncd.conf/ntp.keys/chrony.keys ungated; .rhosts/hosts.equiv matched; `isOsLoginBannerFile` exported user contribution (issue/issue.net/motd ungated; motd.d//issue.d//update-motd.d/ dir membership); distinct from WS-67 (auditd, AppArmor/seccomp k8s), WS-68 (iptables/nftables — WS-89 covers TCP wrappers hosts.allow/deny), WS-70 (pam.d/ auth stack — WS-89 covers sudoers), WS-84 (OpenVPN/WireGuard — WS-89 covers sshd_config); max score 73 = 'high' (3M×8=24 not hitting cap-25; 4H×15=60 capped at 45; 1L×4=4); 4 test fixes (score 45 boundary → 'high'; max-score 73 not 85); 131 tests; `osSecurityHardeningDriftResults` schema table (2 indexes); `convex/osSecurityHardeningDriftIntel.ts` (6 entrypoints: recordOsSecurityHardeningDriftScan/triggerOsSecurityHardeningDriftScan/getLatestOsSecurityHardeningDriftScan/getLatestOsSecurityHardeningDriftBySlug/getOsSecurityHardeningDriftScanHistory/getOsSecurityHardeningDriftSummaryByTenant); fire-and-forget in events.ts before WS-88; `GET /api/repository/os-security-hardening-drift` HTTP route; `api.d.ts` registration; `RepositoryOsSecurityHardeningDriftPanel` dashboard component. All checks green (7045/7045 tests, 112 files).
- WS-88 DNS Security Configuration Drift Detector now complete: `convex/lib/dnsSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (BIND_DNS_CONFIG_DRIFT/UNBOUND_RESOLVER_DRIFT/POWERDNS_CONFIG_DRIFT/COREDNS_CONFIG_DRIFT high; DNSMASQ_CONFIG_DRIFT/PIHOLE_CONFIG_DRIFT/DNS_OVER_HTTPS_CONFIG_DRIFT medium; DNS_RPKI_VALIDATION_DRIFT low); named.conf/named-local.conf/named-options.conf/named.conf.local/named.conf.options/rndc.conf/rndc.key ungated (BIND_UNGATED all lowercase); named.conf.* prefix convention ungated; db.* zone file prefix in BIND_DIRS (BIND db.<domain> zone file naming); corefile ungated (globally unambiguous CoreDNS entry point); unbound.conf/unbound-anchor.conf/unbound-control.conf ungated; pdns.conf/pdns-recursor.conf/recursor.yml ungated; recursor.conf gated on POWERDNS_DIRS (too generic ungated); dnsmasq.conf ungated + dnsmasq.d directory match; pihole.conf/ftl.conf/.pihole.conf ungated; dnscrypt-proxy.toml/dnscrypt-proxy.yaml/stubby.yml/stubby.yaml/.stubby.yml ungated (DOH_UNGATED all lowercase); dnscrypt- prefix + .toml/.conf/.yaml/.yml ext; `isDnsRpkiValidatorConfig` exported user contribution (IaC exclusion [terraform/pulumi] → routinator.conf/fort.conf/rpki-client.conf/stayrtr.conf/gortr.conf ungated → rpki-*/routinator-*/fort-* prefix → RPKI_DIRS membership); distinct from WS-68 (DNSSEC key material .key/.private files in dns/bind/named/dnssec/ dirs); 2 test fixes (db.* zone file startsWith check; dnscrypt- prefix .yaml/.yml extension); 132 tests; `dnsSecurityDriftResults` schema table (2 indexes); `convex/dnsSecurityDriftIntel.ts` (6 entrypoints: recordDnsSecurityDriftScan/triggerDnsSecurityDriftScan/getLatestDnsSecurityDriftScan/getLatestDnsSecurityDriftBySlug/getDnsSecurityDriftScanHistory/getDnsSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-87; `GET /api/repository/dns-security-drift` HTTP route; `api.d.ts` registration; `RepositoryDnsSecurityDriftPanel` dashboard component. All checks green (6914/6914 tests, 111 files).
- WS-87 Storage & Data Security Configuration Drift Detector now complete: `convex/lib/storageDataSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (NFS_EXPORT_CONFIG_DRIFT/SMB_CIFS_CONFIG_DRIFT/STORAGE_ENCRYPTION_CONFIG_DRIFT/OBJECT_STORAGE_CLIENT_DRIFT high; DATABASE_BACKUP_ENCRYPTION_DRIFT/FILE_INTEGRITY_MONITORING_DRIFT/DATA_LOSS_PREVENTION_CONFIG_DRIFT medium; STORAGE_AUDIT_CONFIG_DRIFT low); crypttab ungated globally unambiguous (LUKS device map); nfs-ganesha.conf/ganesha.conf/nfs.conf ungated; smb.conf/samba.conf/smb4.conf/lmhosts ungated; pgbackrest.conf/pgbackrest.ini/.pgbackrest.conf/barman.conf/.barman.conf/barman-server.conf ungated; aide.conf/tripwire.cfg/tripwire-local.cfg/twcfg.txt/samhain.conf/.samhainrc ungated; dlp-config.yaml/dlp-policy.yaml/data-classification.yaml/data-loss-prevention.yaml ungated; minio-audit.env/storage-audit.yaml/minio-audit-config.yaml ungated; `isObjectStorageClientConfig` exported user contribution (IaC dir exclusion [terraform/pulumi/cdk/cloudformation] + CI dir exclusion [.github/.gitlab/.circleci/.buildkite] → .s3cfg/.boto ungated → credentials in aws/ path → .aws/config → MinIO .mc/config.json → s3-config/aws-credentials/gcs-credentials/azure-storage- prefix → object storage dir membership); distinct from WS-62 (cloud IAM bucket policies), WS-70 (Vault access policies/LDAP), WS-85 (backup agents: rclone/restic/borg); 143 tests (3 test-logic fixes: vendor path tests moved from rule.match to scanner integration level); `storageDataSecurityDriftResults` schema table (2 indexes); `convex/storageDataSecurityDriftIntel.ts` (6 entrypoints: recordStorageDataSecurityDriftScan/triggerStorageDataSecurityDriftScan/getLatestStorageDataSecurityDriftScan/getLatestStorageDataSecurityDriftBySlug/getStorageDataSecurityDriftScanHistory/getStorageDataSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-86; `GET /api/repository/storage-data-security-drift` HTTP route; `api.d.ts` registration; `RepositoryStorageDataSecurityDriftPanel` dashboard component. All checks green (6782/6782 tests, 110 files).
- WS-86 SIEM & Security Analytics Configuration Drift Detector now complete: `convex/lib/siemSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (SPLUNK_DETECTION_CONFIG_DRIFT/ELASTIC_SIEM_RULE_DRIFT/SENTINEL_ANALYTICS_DRIFT/OSQUERY_CONFIG_DRIFT high; SIEM_DETECTION_SUPPRESSION_DRIFT/SOAR_PLAYBOOK_DRIFT/THREAT_INTEL_FEED_DRIFT medium; SIEM_LOG_SOURCE_DRIFT low); savedsearches.conf/alert_actions.conf/correlationsearches.conf/notable_event_actions.conf ungated (SPLUNK_UNGATED, all lowercase); analyticsrules.json/analyticsrules.yaml/huntingqueries.json/huntingqueries.yaml ungated (SENTINEL_UNGATED); osquery.conf/.osquery.conf/osquery.flags/osquery.example.conf ungated (OSQUERY_UNGATED); xsoar-config.yaml/xsoar-config.json/demisto-config.yaml/phantom-config.json/splunk-soar-config.yaml ungated (SOAR_UNGATED); misp.conf/misp-config.yaml/opencti.yml/opencti.yaml/taxii-config.json/stix-config.yaml ungated (THREAT_INTEL_UNGATED); detection-exceptions.yaml/alert-exceptions.yaml/suppression-rules.yaml/detection-suppressions.yaml ungated (SUPPRESSION_UNGATED); Elastic SIEM uses .toml extension in ELASTIC_SIEM_DIRS (detection-rules/elastic-siem/security-rules/siem-rules) + exception-list compound check; `isSiemDetectionRuleFile` exported user contribution (excludes terraform/pulumi/cdk/cloudformation dirs, .github/.gitlab/.circleci/.buildkite dirs, prometheus-rules/alert-rules/alertmanager dirs (WS-71 territory), sigma/yara/falco dirs (WS-67 territory); positively matches threat-intel keyword in base + config extension, or any config file inside THREAT_INTEL_DIRS); double-fire design: splunk/inputs.conf triggers both SPLUNK_DETECTION_CONFIG (`.conf` in splunk/ dirs) AND SIEM_LOG_SOURCE (inputs.conf in splunk/ dirs) — test scoring must use non-overlapping files like siem-inputs/windows-events.yaml for single-LOW-only tests; distinct from WS-15 (SIEM push connectors), WS-67 (host-level enforcement: Falco/OPA/Sigma/YARA/auditd), WS-71 (log pipeline: Fluentd/Logstash/Prometheus/Alertmanager); 142 tests; `siemSecurityDriftResults` schema table (2 indexes); `convex/siemSecurityDriftIntel.ts` (6 entrypoints: recordSiemSecurityDriftScan/triggerSiemSecurityDriftScan/getLatestSiemSecurityDriftScan/getLatestSiemSecurityDriftBySlug/getSiemSecurityDriftScanHistory/getSiemSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-85; `GET /api/repository/siem-security-drift` HTTP route; `api.d.ts` registration; `RepositorySiemSecurityDriftPanel` dashboard component. All checks green (6639/6639 tests, 109 files).
- WS-85 Backup & Disaster Recovery Security Configuration Drift Detector now complete: `convex/lib/backupDrSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (RCLONE_CONFIG_DRIFT/RESTIC_BACKUP_DRIFT/BORGBACKUP_DRIFT/BACKUP_ENCRYPTION_CREDENTIAL_DRIFT high; RSYNC_DAEMON_DRIFT/ENTERPRISE_BACKUP_DRIFT/CLOUD_BACKUP_AGENT_DRIFT medium; BACKUP_SCRIPT_DRIFT low); rclone.conf/.rclone.conf ungated (stores credentials for every cloud provider); restic-password/restic-password.txt/.restic-password/restic-password-file/restic.conf ungated; borgmatic.yaml/borgmatic.yml/.borgmatic.yaml/borgpassphrase/.borgpassphrase/borg-passphrase ungated; rsyncd.conf/rsyncd.secrets ungated; bacula-dir.conf/bacula-fd.conf/bacula-sd.conf/amanda.conf/amanda-client.conf ungated; credentials-velero/velero-credentials ungated; `isBackupEncryptionCredential` exported user contribution (excludes files already caught by specific rules, CI/CD dir exclusion, globally unambiguous backup credential basenames, BACKUP_CRED_DIRS gating, credential extension check); 133 tests; `backupDrSecurityDriftResults` schema table (2 indexes); `convex/backupDrSecurityDriftIntel.ts` (6 entrypoints: recordBackupDrSecurityDriftScan/triggerBackupDrSecurityDriftScan/getLatestBackupDrSecurityDriftScan/getLatestBackupDrSecurityDriftBySlug/getBackupDrSecurityDriftScanHistory/getBackupDrSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-84; `GET /api/repository/backup-dr-security-drift` HTTP route; `api.d.ts` registration; `RepositoryBackupDrSecurityDriftPanel` dashboard component. All checks green (6497/6497 tests, 108 files).
- WS-82 Package & Artifact Registry Security Configuration Drift Detector now complete: `convex/lib/artifactRegistryDrift.ts` — pure library, 8 rules across 3 severity tiers (ARTIFACTORY_CONFIG_DRIFT/NEXUS_CONFIG_DRIFT/HARBOR_REGISTRY_DRIFT/DOCKER_REGISTRY_DRIFT high; NPM_REGISTRY_DRIFT/PYPI_REGISTRY_DRIFT/HELM_CHART_REPO_DRIFT medium; GO_MODULE_PROXY_DRIFT low); 5-level risk model; artifactory.system.yaml/artifactory.config.xml/artifactory.lic ungated; nexus.properties/nexus-default.properties ungated; harbor.yml/harbor.yaml/harbor-v1.10.yml ungated; docker-registry-config.yaml/registry-config.yaml ungated; verdaccio.yaml/sinopia.yaml ungated; bandersnatch.cfg/bandersnatch.ini/devpi-server.cfg/devpi.ini/warehouse.cfg ungated; chartmuseum.yaml/chartmuseum.yml/chartmuseum.json ungated; athens.yaml/athens.toml/.athens.yaml ungated; `isDockerRegistryConfig` exported user contribution (IaC/CI dir exclusion [terraform/pulumi/cdk/k8s/kubernetes/helm/.github/.gitlab/.circleci/.buildkite] → registry-keyword in basename [registry-auth/registry-tls/registry-mirror/registry-config] + config ext → must be in REGISTRY_DIRS [registry/docker-registry/container-registry/distribution] + structural name [config.yml/auth.yaml/htpasswd/nginx.conf]); 158 tests; `artifactRegistryDriftResults` schema table (2 indexes); `convex/artifactRegistryDriftIntel.ts` (6 entrypoints: recordArtifactRegistryDriftScan/triggerArtifactRegistryDriftScan/getLatestArtifactRegistryDriftScan/getLatestArtifactRegistryDriftBySlug/getArtifactRegistryDriftScanHistory/getArtifactRegistryDriftSummaryByTenant); fire-and-forget in events.ts before WS-81; `GET /api/repository/artifact-registry-drift` HTTP route; `api.d.ts` registration; `RepositoryArtifactRegistryDriftPanel` dashboard component. All checks green (6065/6065 tests, 105 files).
- WS-81 ML/AI Platform Security Configuration Drift Detector now complete: `convex/lib/mlAiPlatformDrift.ts` — pure library, 8 rules across 3 severity tiers (MLFLOW_TRACKING_DRIFT/KUBEFLOW_PIPELINE_DRIFT/RAY_CLUSTER_DRIFT/AI_PLATFORM_ACCESS_DRIFT high; FEATURE_STORE_DRIFT/MODEL_SERVING_DRIFT/MLOPS_PIPELINE_DRIFT medium; MODEL_CARD_AUDIT_DRIFT low); 5-level risk model; mlflow.yaml/mlflow-config.yaml/mlflow-tracking.yaml ungated; kfctl.yaml/kfdef.yaml ungated Kubeflow CRDs; ray-cluster.yaml/anyscale-config.yaml ungated; sagemaker.yaml/.sagemaker.json ungated; feature_store.yaml/feast.yaml ungated (Feast canonical — globally unambiguous); bentofile.yaml/seldon-deployment.yaml/inferenceservice.yaml/torchserve.config ungated; dvc.yaml/clearml.conf ungated; model-card.json/modelcard.yaml ungated; `isAiPlatformAccessFile` exported user contribution (IaC/k8s dir exclusion first → platform prefix sagemaker-X/vertexai-X/azureml-X always matches → platform dir required + access keyword in basename [role/permission/access/auth/credential/endpoint/domain/iam/execution/trust/workspace/compute] OR standard IaC config filename); 135 tests; `mlAiPlatformDriftResults` schema table (2 indexes); `convex/mlAiPlatformDriftIntel.ts` (6 entrypoints: recordMlAiPlatformDriftScan/triggerMlAiPlatformDriftScan/getLatestMlAiPlatformDriftScan/getLatestMlAiPlatformDriftBySlug/getMlAiPlatformDriftScanHistory/getMlAiPlatformDriftSummaryByTenant); fire-and-forget in events.ts before WS-80; `GET /api/repository/ml-ai-platform-drift` HTTP route; `api.d.ts` registration; `RepositoryMlAiPlatformDriftPanel` dashboard component. All checks green (5907/5907 tests, 104 files).
- WS-80 Data Pipeline & ETL Security Configuration Drift Detector now complete: `convex/lib/dataPipelineDrift.ts` — pure library, 8 rules across 3 severity tiers (AIRFLOW_SECURITY_DRIFT/SPARK_SECURITY_DRIFT/DBT_CREDENTIALS_DRIFT/HADOOP_ECOSYSTEM_DRIFT high; TRINO_PRESTO_DRIFT/PIPELINE_ORCHESTRATION_DRIFT/DATA_QUALITY_DRIFT medium; NOTEBOOK_SERVER_DRIFT low); 5-level risk model; airflow.cfg/webserver_config.py ungated; spark-defaults.conf/spark-env.sh ungated; dbt_project.yml/dbt_project.yaml ungated; hdfs-site.xml/core-site.xml/yarn-site.xml/hive-site.xml/flink-conf.yaml/ranger-admin-site.xml ungated; trino.properties/presto.properties ungated; dagster.yaml/prefect.yaml/kedro.yml ungated; great_expectations.yml/datahub.yaml/atlas-application.properties ungated; jupyter_notebook_config.py/jupyterhub_config.py ungated; `isDbtProfilesFile` exported user contribution (profiles.yml/profiles.yaml gated on dbt/ dir segment or DBT_DIRS; dbt-profiles.yml always matches ungated); SPARK vs HADOOP overlap: hive-site.xml is in HADOOP_UNGATED (globally unambiguous Hadoop config) so it matches HADOOP rule but NOT SPARK unless also in spark/ dir; 135 tests; `dataPipelineDriftResults` schema table (2 indexes); `convex/dataPipelineDriftIntel.ts` (6 entrypoints: recordDataPipelineDriftScan/triggerDataPipelineDriftScan/getLatestDataPipelineDriftScan/getLatestDataPipelineDriftBySlug/getDataPipelineDriftScanHistory/getDataPipelineDriftSummaryByTenant); fire-and-forget in events.ts before WS-79; `GET /api/repository/data-pipeline-drift` HTTP route; `api.d.ts` registration; `RepositoryDataPipelineDriftPanel` dashboard component. All checks green (5772/5772 tests, 103 files).
- WS-79 SSO Provider & Authentication Configuration Drift Detector now complete: `convex/lib/ssoProviderDrift.ts` — pure library, 8 rules across 3 severity tiers (KEYCLOAK_REALM_DRIFT/SAML_IDP_SP_DRIFT/OAUTH2_OIDC_PROVIDER_DRIFT/HOSTED_IDP_CONFIG_DRIFT high; SSO_MIDDLEWARE_DRIFT/MFA_PROVIDER_DRIFT/SCIM_PROVISIONING_DRIFT medium; IDENTITY_PROXY_DRIFT low); 5-level risk model; realm-export.json/keycloak.json ungated; realm-*.json/keycloak-*.json prefix; realm.json/clients.json/flows.json/users.json gated on KEYCLOAK_DIRS; saml-config.xml/federation-metadata.xml/idp-metadata.xml ungated; saml-*.xml prefix; metadata.xml/sp.xml gated on SAML_DIRS; oidc-config.json/hydra.yml ungated; oauth2-*.yaml/oidc-*.json/hydra-*.yaml prefix; jwks.json/clients.json gated on OAUTH_DIRS; auth0.json/.auth0.json/.okta.yaml/pingfederate.xml ungated; `isHostedIdpConfigFile` exported user contribution (hosted IdP dir required + config ext + IdP keyword in basename OR IdP-structural subpath like connections//actions//flows/); dex.yaml/authelia-config.yml/authentik.env ungated; duo.ini/duo.conf/pam_duo.conf/yubikey.conf ungated; scim-config.json/scim.yaml ungated; oauth2-proxy.cfg/oauth2-proxy.yaml/oauth2-proxy.toml ungated; 135 tests; `ssoProviderDriftResults` schema table (2 indexes); `convex/ssoProviderDriftIntel.ts` (6 entrypoints: recordSsoProviderDriftScan/triggerSsoProviderDriftScan/getLatestSsoProviderDriftScan/getLatestSsoProviderDriftBySlug/getSsoProviderDriftScanHistory/getSsoProviderDriftSummaryByTenant); fire-and-forget in events.ts before WS-78; `GET /api/repository/sso-provider-drift` HTTP route; `api.d.ts` registration; `RepositorySsoProviderDriftPanel` dashboard component.
- WS-78 Messaging & Event Streaming Security Configuration Drift Detector now complete: `convex/lib/messagingSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (KAFKA_SECURITY_DRIFT/RABBITMQ_SECURITY_DRIFT/NATS_SECURITY_DRIFT/MQTT_BROKER_DRIFT high; STREAM_TLS_CONFIG_DRIFT/MESSAGE_AUTH_POLICY_DRIFT/SCHEMA_REGISTRY_DRIFT medium; PUBSUB_BROKER_DRIFT low); 5-level risk model; Kafka uses prefix detection (kafka-*.properties/kafka-*.conf ungated) + canonical names (server.properties/consumer.properties/producer.properties/jaas.conf/kraft.properties/controller.properties/zookeeper.properties) and any .properties in KAFKA_DIRS gated; rabbitmq.conf/rabbitmq-env.conf/rabbitmq.config ungated; nats-server.conf/nats.conf ungated + nats-*.conf prefix; mosquitto.conf/mosquitto.passwd/hivemq-config.xml ungated; kafka-ssl.properties/kafka-tls.properties/amqp-ssl.conf/amqp-tls.conf ungated for TLS (dual-match with KAFKA rule by design); `isMessageAuthPolicyFile` exported user contribution (broker-prefix + auth-keyword ungated OR messaging-dir + config-ext + auth-keyword gated); schema-registry.properties/yml/yaml/apicurio-registry.properties ungated + schema-registry-* prefix; activemq.xml/pulsar-broker.conf ungated; 122 tests; `messagingSecurityDriftResults` schema table (2 indexes); `convex/messagingSecurityDriftIntel.ts` (6 entrypoints: recordMessagingSecurityDriftScan/triggerMessagingSecurityDriftScan/getLatestMessagingSecurityDriftScan/getLatestMessagingSecurityDriftBySlug/getMessagingSecurityDriftScanHistory/getMessagingSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-77; `GET /api/repository/messaging-security-drift` HTTP route; `api.d.ts` registration; `RepositoryMessagingSecurityDriftPanel` dashboard component.
- WS-77 Serverless & FaaS Security Configuration Drift Detector now complete: `convex/lib/serverlessFaasDrift.ts` — pure library, 8 rules across 3 severity tiers (SERVERLESS_FRAMEWORK_DRIFT/AWS_LAMBDA_SAM_DRIFT/AZURE_FUNCTION_SECURITY_DRIFT/CLOUDFLARE_WORKER_DRIFT high; GCP_CLOUD_RUN_DRIFT/EDGE_DEPLOY_CONFIG_DRIFT/FUNCTION_IAM_PERMISSION_DRIFT medium; KNATIVE_OPENWHISK_DRIFT low); 5-level risk model; distinct from WS-60 (app-level JWT/CORS), WS-62 (cloud-wide IAM/KMS), WS-66 (cert PKI material), WS-73 (CI/CD pipeline orchestration); serverless.yml/yaml/ts/json globally unambiguous Serverless Framework configs; serverless.*.yml/yaml stage configs caught by prefix+suffix check; samconfig.toml/yaml/yml globally unambiguous AWS SAM; template.yaml/yml/json gated on SAM_DIRS/LAMBDA_DIRS (too generic ungated); local.settings.json globally unambiguous Azure Functions; function.json/host.json gated on AZURE_DIRS (lowercased: httptrigger//blobtrigger//timertrigger// fixed case-sensitivity bug); wrangler.toml/json/jsonc/yaml globally unambiguous Cloudflare Workers; wrangler.*/wrangler-* stage variants; cloud-run-service.yaml/cloud-run-job.yaml/cloudfunctions.yaml ungated GCP; service.yaml/app.yaml gated on GCP_DIRS; netlify.toml/fly.toml/vercel.json/render.yaml ungated edge platform configs; wskprops/.wskprops ungated OpenWhisk CLI config; Knative CRD names gated on KNATIVE_DIRS; `isFunctionIamPermissionFile` exported user contribution (gated on LAMBDA_DIRS + JSON/YAML extension + IAM keyword in filename: role/policy/permission/iam/execution/trust/assume); 124 tests; `serverlessFaasDriftResults` schema table (2 indexes); `convex/serverlessFaasDriftIntel.ts` (6 entrypoints: recordServerlessFaasDriftScan/triggerServerlessFaasDriftScan/getLatestServerlessFaasDriftScan/getLatestServerlessFaasDriftBySlug/getServerlessFaasDriftScanHistory/getServerlessFaasDriftSummaryByTenant); fire-and-forget in events.ts before WS-76; `GET /api/repository/serverless-faas-drift` HTTP route; `api.d.ts` registration; `RepositoryServerlessFaasDriftPanel` dashboard component.
- WS-76 Email Security Configuration Drift Detector now complete: `convex/lib/emailSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (SMTP_SERVER_CONFIG_DRIFT/DKIM_SIGNING_CONFIG_DRIFT/MAIL_AUTH_SASL_DRIFT high; ANTISPAM_FILTER_DRIFT/MAIL_TLS_SECURITY_DRIFT/MAIL_RELAY_RESTRICTIONS_DRIFT/MAIL_ACCESS_POLICY_DRIFT medium; MAIL_HEADER_FILTER_DRIFT low); 5-level risk model; distinct from WS-60 (app-level TLS/session), WS-66 (cert PKI material), WS-68 (OS-level firewall), WS-75 (HTTP ingress edge); sendmail.cf/sendmail.mc/exim.conf/exim4.conf/dovecot.conf globally unambiguous MTA names; opendkim.conf/opendmarc.conf/amavisd.conf/amavis.conf/rspamd.conf globally unambiguous daemon configs; main.cf/master.cf gated on postfix/ dir; DKIM key material gated on dkim/ dir; `isMailAuthSaslConfig` user contribution (saslauthd.conf/cyrus.conf ungated; smtpd.conf gated on sasl/ dirs; *.conf in SASL_DIRS; sasl.conf gated on MAIL_DIRS to avoid OpenLDAP false positives); relay map names (relay_domains/transport/virtual/canonical) gated on postfix/ dir; access map names (access/sender_access/recipient_access/client_access/helo_access) gated on postfix/ dir; header filter names (header_checks/body_checks/mime_header_checks) gated on postfix/ dir; milter configs gated on milter/ dirs; 125 tests; `emailSecurityDriftResults` schema table (2 indexes); `convex/emailSecurityDriftIntel.ts` (6 entrypoints: recordEmailSecurityDriftScan/triggerEmailSecurityDriftScan/getLatestEmailSecurityDriftScan/getLatestEmailSecurityDriftBySlug/getEmailSecurityDriftScanHistory/getEmailSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-75; `GET /api/repository/email-security-drift` HTTP route; `api.d.ts` registration; `RepositoryEmailSecurityDriftPanel` dashboard component.
- WS-75 Web Server & Reverse Proxy Security Configuration Drift Detector now complete: `convex/lib/webServerSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (NGINX_SECURITY_CONFIG_DRIFT/APACHE_SECURITY_CONFIG_DRIFT/TRAEFIK_SECURITY_CONFIG_DRIFT high; CADDY_SECURITY_CONFIG_DRIFT/INGRESS_CONTROLLER_SECURITY_DRIFT/MOD_SECURITY_WAF_DRIFT/SSL_TERMINATION_CONFIG_DRIFT medium; WEB_SERVER_ACCESS_CONTROL_DRIFT low); 5-level risk model; distinct from WS-60 (app-level TLS/CORS), WS-63 (k8s RBAC/NetworkPolicy), WS-68 (OS-level firewall/iptables), WS-72 (Istio/Envoy east-west); nginx.conf/Caddyfile/traefik.yml globally unambiguous; .htaccess globally unambiguous (Apache only); sites-available/sites-enabled gated under NGINX rule; `isIngressSecurityConfig` user contribution (ingress-nginx.yaml/nginx-ingress.yaml/haproxy-ingress.yaml/traefik-ingress.yaml/kong-ingress.yaml ungated; ingress-nginx-*/nginx-ingress-* compound prefix; ingress.yaml/values.yaml/ingress.yml gated on ingress//ingress-nginx//nginx-ingress//traefik-ingress//haproxy-ingress//kong-ingress/ dirs; non-security YAMLs like deployment.yaml excluded); ssl.conf/tls.conf gated on ssl//tls//certs/ only (not nginx//apache/ to avoid double-counting with nginx/apache rules); crs-setup.conf/modsecurity.conf globally unambiguous OWASP CRS; REQUEST-*/RESPONSE-*.conf OWASP numbered rule files; dhparam.pem/options-ssl-nginx.conf SSL param files; .htpasswd globally unambiguous basic auth; geo.conf gated on nginx//geoip/ for IP access control; 5131 tests (138 new); `webServerSecurityDriftResults` schema table (2 indexes); `convex/webServerSecurityDriftIntel.ts` (6 entrypoints: recordWebServerSecurityDriftScan/triggerWebServerSecurityDriftScan/getLatestWebServerSecurityDriftScan/getLatestWebServerSecurityDriftBySlug/getWebServerSecurityDriftScanHistory/getWebServerSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-74; `GET /api/repository/web-server-security-drift` HTTP route; `api.d.ts` registration; `RepositoryWebServerSecurityDriftPanel` dashboard component.
- WS-74 Mobile Application Security Configuration Drift Detector now complete: `convex/lib/mobileAppSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (IOS_ENTITLEMENTS_DRIFT/ANDROID_MANIFEST_DRIFT/MOBILE_SIGNING_CONFIG_DRIFT/IOS_APP_SECURITY_CONFIG_DRIFT high; ANDROID_OBFUSCATION_CONFIG_DRIFT/MOBILE_FIREBASE_CONFIG_DRIFT/MOBILE_DEEP_LINK_CONFIG_DRIFT medium; MOBILE_PLATFORM_CONFIG_DRIFT low); 5-level risk model; distinct from WS-60 (server-side TLS/CORS), WS-66 (cert pinning/SSH key material), WS-68 (server network perimeter), WS-70 (server IAM); .entitlements extension globally unambiguous for Apple platform apps; ExportOptions.plist unambiguous for iOS code signing; AndroidManifest.xml globally unambiguous; `isAndroidManifestSecurityFile` user contribution point (test source-set exclusion: androidTest/, /test/, testDebug/, testRelease/ excluded; production, debug, and flavour manifests included); .mobileprovision/.jks/.keystore extension globally unambiguous for signing; key.properties gated on android/ dir (Flutter); PrivacyInfo.xcprivacy globally unambiguous Apple Privacy Manifest (.xcprivacy extension exclusive to Apple); Info.plist gated on IOS_DIRS (ios/, macos/, osx/, watchos/, tvos/, visionos/, xcodeproj/, xcworkspace/, runner/); proguard-rules.pro/consumer-rules.pro/r8-rules.txt globally unambiguous Android obfuscation filenames; proguard- prefix + proguard/ dir detection; google-services.json/GoogleService-Info.plist/firebase.json/.firebaserc globally unambiguous Firebase config; apple-app-site-association (no extension) globally unambiguous for Universal Links; assetlinks.json gated on .well-known/ dir; digital-asset-links.json globally unambiguous; eas.json/capacitor.config.json/ionic.config.json/Podfile.lock globally unambiguous; .xcconfig gated on IOS_DIRS; 144 tests; `mobileAppSecurityDriftResults` schema table (2 indexes); `convex/mobileAppSecurityDriftIntel.ts` (6 entrypoints: recordMobileAppSecurityDriftScan/triggerMobileAppSecurityDriftScan/getLatestMobileAppSecurityDriftScan/getLatestMobileAppSecurityDriftBySlug/getMobileAppSecurityDriftScanHistory/getMobileAppSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-73; `GET /api/repository/mobile-app-security-drift` HTTP route; `api.d.ts` registration; `RepositoryMobileAppSecurityDriftPanel` dashboard component.
- WS-73 CI/CD Pipeline Security Configuration Drift Detector now complete: `convex/lib/cicdPipelineSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (GITHUB_ACTIONS_WORKFLOW_DRIFT/JENKINS_PIPELINE_SECURITY_DRIFT/GITLAB_CI_SECURITY_DRIFT high; ARGOCD_APP_SECURITY_DRIFT/FLUX_GITOPS_SECURITY_DRIFT/BUILDKITE_CIRCLECI_DRIFT/TEKTON_PIPELINE_DRIFT medium; PIPELINE_ARTIFACT_SIGNING_DRIFT low); 5-level risk model; distinct from WS-05 (CI/CD integration setup), WS-57 (security source code), WS-63 (k8s RBAC/NetworkPolicy), WS-66 (signing key material); `.github/workflows/` unambiguous for GitHub Actions; `.gitlab-ci.yml` globally unambiguous; `.circleci/` and `.buildkite/` dir segments unambiguous; `appproject.yaml`/`applicationset.yaml` globally unambiguous ArgoCD CRDs; `helmrelease.yaml`/`gitrepository.yaml`/`imagepolicy.yaml` globally unambiguous FluxCD CRDs; `kustomization.yaml` gated on flux/ dir (also used by Kustomize standalone); `isTektonPipelineConfig` user contribution (k8s/manifests/helm/ dir exclusion + globally unambiguous Tekton CRDs: clustertask.yaml/taskrun.yaml/pipelinerun.yaml/stepaction.yaml + tekton/ dir context for ambiguous task.yaml/pipeline.yaml + tekton- prefix); SLSA detection via slsa-goreleaser/slsa-policy/slsa-verifier exact names + slsa/ dir + slsa- prefix; removed unused SLSA_EXACT constant; 150 tests; `cicdPipelineSecurityDriftResults` schema table (2 indexes); `convex/cicdPipelineSecurityDriftIntel.ts` (6 entrypoints: recordCicdPipelineSecurityDriftScan/triggerCicdPipelineSecurityDriftScan/getLatestCicdPipelineSecurityDriftScan/getLatestCicdPipelineSecurityDriftBySlug/getCicdPipelineSecurityDriftScanHistory/getCicdPipelineSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-72; `GET /api/repository/cicd-pipeline-security-drift` HTTP route; `api.d.ts` registration; `RepositoryCicdPipelineSecurityDriftPanel` dashboard component.
- WS-72 Service Mesh & Zero-Trust Network Security Configuration Drift Detector now complete: `convex/lib/serviceMeshSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (ISTIO_AUTH_POLICY_DRIFT/ENVOY_PROXY_SECURITY_DRIFT/SPIFFE_SPIRE_DRIFT high; LINKERD_SECURITY_POLICY_DRIFT/CONSUL_CONNECT_DRIFT/CNI_NETWORK_POLICY_DRIFT/ZERO_TRUST_ACCESS_DRIFT medium; MESH_GATEWAY_DRIFT low); 5-level risk model; distinct from WS-63 (base k8s NetworkPolicy/RBAC), WS-67 (OPA/Rego runtime enforcement), WS-68 (host-level iptables/nftables); k8s dir exclusion applied first in `isIstioPolicyFile` (before exact-basename check) to prevent peer-authentication.yaml in k8s/ from matching; serviceentry.yaml/service-entry.yaml in GATEWAY_UNGATED (globally unambiguous Istio CRD names); `isCniNetworkPolicyConfig` user contribution point (k8s/kubernetes/kustomize/helm/charts/manifests/ exclusion → Cilium exact filenames: cilium.yaml/ciliumnetworkpolicy.yaml/clusterwidenetworkpolicy.yaml/cni-config.json → Calico exact: calicoctl.cfg/globalnetworkpolicy.yaml/felixconfiguration.yaml → Antrea exact: antrea.yaml/clusternetworkpolicy.yaml → CNI dir context: cilium//calico//antrea//cni//network-policies/ → cilium-/calico-/antrea- prefix); removed unused LINKERD_EXACT and ZERO_TRUST_EXACT constants (used LINKERD_UNGATED_EXACT and ZERO_TRUST_UNGATED subsets instead); 154 tests; `serviceMeshSecurityDriftResults` schema table (2 indexes); `convex/serviceMeshSecurityDriftIntel.ts` (6 entrypoints: recordServiceMeshSecurityDriftScan/triggerServiceMeshSecurityDriftScan/getLatestServiceMeshSecurityDriftScan/getLatestServiceMeshSecurityDriftBySlug/getServiceMeshSecurityDriftScanHistory/getServiceMeshSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-71; `GET /api/repository/service-mesh-security-drift` HTTP route; `api.d.ts` registration; `RepositoryServiceMeshSecurityDriftPanel` dashboard component.
- WS-71 Observability & Security Monitoring Configuration Drift Detector now complete: `convex/lib/observabilitySecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (PROMETHEUS_ALERT_RULES_DRIFT/ALERTMANAGER_CONFIG_DRIFT/LOG_PIPELINE_SECURITY_DRIFT high; OTEL_COLLECTOR_DRIFT/GRAFANA_SECURITY_DRIFT/CLOUDWATCH_ALARM_DRIFT/TRACING_SECURITY_DRIFT medium; LOG_RETENTION_POLICY_DRIFT low); 5-level risk model; distinct from WS-15 (SIEM push connectors), WS-62 (CloudTrail/IaC audit configs), WS-67 (auditd kernel source); prometheus.yml (scrape config) excluded, *.rules.yml/.rules.yaml suffix unambiguous; alertmanager.yml/alertmanager.yaml unambiguous exact; fluent.conf/logstash.conf/vector.toml/filebeat.yml unambiguous tool signals; grafana.ini ungated, grafana.yaml requires grafana/ directory; cloudwatch- prefix or cloudwatch/ dir required; `isTracingSecurityConfig` user contribution (k8s/helm/IaC directory exclusion + Jaeger/Tempo/Zipkin exact filenames + tracing/ dir context); 144 tests; `observabilitySecurityDriftResults` schema table (2 indexes); `convex/observabilitySecurityDriftIntel.ts` (6 entrypoints: recordObservabilitySecurityDriftScan/triggerObservabilitySecurityDriftScan/getLatestObservabilitySecurityDriftScan/getLatestObservabilitySecurityDriftBySlug/getObservabilitySecurityDriftScanHistory/getObservabilitySecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-70; `GET /api/repository/observability-security-drift` HTTP route; `api.d.ts` registration; `RepositoryObservabilitySecurityDriftPanel` dashboard component.
- WS-70 Identity & Privileged Access Management Configuration Drift Detector now complete: `convex/lib/identityAccessDrift.ts` — pure library, 8 rules across 3 severity tiers (VAULT_POLICY_DRIFT/LDAP_CONFIG_DRIFT/PRIVILEGED_ACCESS_DRIFT high; MFA_ENFORCEMENT_DRIFT/IDENTITY_FEDERATION_DRIFT/SERVICE_ACCOUNT_DRIFT/PASSWORD_POLICY_DRIFT medium; APPLICATION_RBAC_DRIFT low); 5-level risk model; distinct from WS-60 (OAuth CLIENT configs), WS-62 (cloud IAM resource policies), WS-63 (k8s RBAC); vault- prefixed HCL unambiguous for Vault; PAM files in pam.d/ are high-confidence; LDAP exact filenames (ldap.conf/slapd.conf/sssd.conf) unambiguous; `isServiceAccountFile` user contribution point (k8s directory exclusion: k8s/kubernetes/kustomize/helm/charts/, IaC exclusion: terraform/pulumi/cdk/, GCP key file *-sa.json and *-service-account.json patterns, workload identity federation files, IAM/credentials directory context); Casbin/Oso/CASL/OpenFGA detected by exact names or casbin/ / authz/ / fga/ directory; 145 tests; `identityAccessDriftResults` schema table (2 indexes); `convex/identityAccessDriftIntel.ts` (6 entrypoints: recordIdentityAccessDriftScan/triggerIdentityAccessDriftScan/getLatestIdentityAccessDriftScan/getLatestIdentityAccessDriftBySlug/getIdentityAccessDriftScanHistory/getIdentityAccessDriftSummaryByTenant); fire-and-forget in events.ts before WS-69; `GET /api/repository/identity-access-drift` HTTP route; `api.d.ts` registration; `RepositoryIdentityAccessDriftPanel` dashboard component.
- WS-69 Developer Security Tooling & SAST Configuration Drift Detector now complete: `convex/lib/devSecToolsDrift.ts` — pure library, 8 rules across 3 severity tiers (SECRET_SCAN_CONFIG_DRIFT/SAST_POLICY_DRIFT/SCA_POLICY_DRIFT high; SECURITY_LINT_DRIFT/DAST_SCAN_CONFIG_DRIFT/LICENSE_POLICY_CONFIG_DRIFT/CONTAINER_SCAN_POLICY_DRIFT medium; SECURITY_BASELINE_DRIFT low); 5-level risk model; distinct from WS-33 (IaC scan findings), WS-35 (CI/CD findings), WS-67 (OPA runtime enforcement); dot-prefixed exact filenames (.gitleaks.toml/.snyk/.brakeman.yml) are unambiguous tool-owner signals; `isDastScanConfigFile` user contribution point handles DAST config vs. result artifact ambiguity via result-keyword exclusion (report/result/output/finding/log takes precedence over all positive signals), canonical exact names (nikto.conf/zap.conf), tool-prefix+config-keyword detection, and DAST directory context (zap/burp/nuclei/dast/pentest); 142 tests; `devSecToolsDriftResults` schema table (2 indexes); `convex/devSecToolsDriftIntel.ts` (6 entrypoints: recordDevSecToolsDriftScan/triggerDevSecToolsDriftScan/getLatestDevSecToolsDriftScan/getLatestDevSecToolsDriftBySlug/getDevSecToolsDriftScanHistory/getDevSecToolsDriftSummaryByTenant); fire-and-forget in events.ts before WS-68; `GET /api/repository/dev-sec-tools-drift` HTTP route; `api.d.ts` registration; `RepositoryDevSecToolsDriftPanel` dashboard component.
- WS-68 Network Perimeter & Firewall Configuration Drift Detector now complete: `convex/lib/networkFirewallDrift.ts` — pure library, 8 rules across 3 severity tiers (IPTABLES_RULES_DRIFT/NFTABLES_CONFIG_DRIFT/HAPROXY_SECURITY_CONFIG_DRIFT high; UFW_RULES_DRIFT/VPN_SECURITY_CONFIG_DRIFT/DNS_SECURITY_DRIFT/PROXY_ACCESS_CONFIG_DRIFT medium; FIREWALLD_ZONE_DRIFT low); 5-level risk model; distinct from WS-62 (cloud infrastructure IAM/KMS), WS-63 (k8s NetworkPolicy), WS-67 (runtime detection — fail2ban/IDS); .nft extension unambiguous for nftables; .ovpn unambiguous for OpenVPN; iptables uses exact filenames (rules.v4/rules.v6/iptables.rules) to avoid collision with WS-67 auditd .rules files; UFW gated-exact set (user.rules/before.rules/after.rules) requires ufw/ directory to prevent false positives on generic filenames; DNSSEC .key/.private files gated on dns/bind/named/dnssec/ directories; `isProxyAccessConfig` user contribution point (squid.conf unambiguous + access-keyword detection: blacklist/whitelist/geo-block/acl/ip-block + proxy directory context gating + Traefik IP-whitelist middleware); firewalld zone names gated on firewalld/ directory; 97 tests; `networkFirewallDriftResults` schema table (2 indexes); `convex/networkFirewallDriftIntel.ts` (6 entrypoints: recordNetworkFirewallDriftScan/triggerNetworkFirewallDriftScan/getLatestNetworkFirewallDriftScan/getLatestNetworkFirewallDriftBySlug/getNetworkFirewallDriftScanHistory/getNetworkFirewallDriftSummaryByTenant); fire-and-forget in events.ts before WS-67; `GET /api/repository/network-firewall-drift` HTTP route; `api.d.ts` registration; `RepositoryNetworkFirewallDriftPanel` dashboard component.
- WS-67 Runtime Security Policy & Enforcement Configuration Drift Detector now complete: `convex/lib/runtimeSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (FALCO_RULES_DRIFT/OPA_REGO_POLICY_DRIFT/SECCOMP_APPARMOR_DRIFT high; KYVERNO_POLICY_DRIFT/FAIL2BAN_CONFIG_DRIFT/AUDITD_RULES_DRIFT/IDS_RULES_DRIFT medium; SIGMA_YARA_RULE_DRIFT low); 5-level risk model (none/low/medium/high/critical); distinct from WS-60 (app TLS options/CORS), WS-62 (cloud IAM/KMS), WS-63 (k8s admission webhook registration/OPA-Gatekeeper); .rego extension is unambiguous OPA signal; fail2ban uses exact filenames (jail.conf/jail.local) + fail2ban/ directory segment; auditd covers audit.rules/auditd.conf/auditbeat.yml + /etc/audit/ path; SIGMA_YARA directory terms without leading slash for root-relative path compatibility; `isIdsRuleFile` user contribution point (Snort/Suricata .conf/.rules + /snort//suricata//ids/ directory gating, Zeek .zeek in /zeek/ dirs); leading-slash-agnostic directory matching pattern (e.g. `fail2ban/` not `/fail2ban/`) applied throughout; 105 tests; `runtimeSecurityDriftResults` schema table (2 indexes); `convex/runtimeSecurityDriftIntel.ts` (6 entrypoints: recordRuntimeSecurityDriftScan/triggerRuntimeSecurityDriftScan/getLatestRuntimeSecurityDriftScan/getLatestRuntimeSecurityDriftBySlug/getRuntimeSecurityDriftScanHistory/getRuntimeSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-66; `GET /api/repository/runtime-security-drift` HTTP route; `api.d.ts` registration; `RepositoryRuntimeSecurityDriftPanel` dashboard component.
- WS-66 Cryptographic Certificate & PKI Configuration Drift Detector now complete: `convex/lib/certPkiDrift.ts` — pure library, 8 rules across 3 severity tiers (CERT_MANAGER_CONFIG_DRIFT/PKI_CA_CONFIG_DRIFT/LETS_ENCRYPT_CONFIG_DRIFT high; CERTIFICATE_PINNING_CONFIG_DRIFT/SSH_AUTH_KEY_DRIFT/GPG_KEYRING_CONFIG_DRIFT/SIGSTORE_COSIGN_CONFIG_DRIFT medium; TLS_CERTIFICATE_BUNDLE_DRIFT low); 5-level risk model (none/low/medium/high/critical); distinct from WS-60 (application TLS options), WS-62 (cloud IAM/KMS), WS-30 (hardcoded secrets); PKI_CA bare 'ca' prefix narrowed to 'ca-'/'ca_' to prevent cacert.pem false-positive collisions with TLS bundle detector; `isCertificatePinningConfig` user contribution point (iOS TrustKit, Android NSC network-security-config.xml, HPKP configs, generic pinning-term detection, /pinning/ directory gating); `certPkiDriftResults` schema table (2 indexes); `convex/certPkiDriftIntel.ts` (6 entrypoints: recordCertPkiDriftScan/triggerCertPkiDriftScan/getLatestCertPkiDriftScan/getLatestCertPkiDriftBySlug/getCertPkiDriftScanHistory/getCertPkiDriftSummaryByTenant); fire-and-forget in events.ts before WS-65; `GET /api/repository/cert-pki-drift` HTTP route; `api.d.ts` registration; `RepositoryCertPkiDriftPanel` dashboard component.
- WS-65 API Security Configuration Drift Detector now complete: `convex/lib/apiSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (API_RATE_LIMIT_DRIFT/API_KEY_MANAGEMENT_DRIFT/GRAPHQL_SECURITY_DRIFT high; OPENAPI_SECURITY_SCHEMA_DRIFT/WEBHOOK_VALIDATION_DRIFT/API_SCHEMA_VALIDATION_DRIFT/REST_API_SECURITY_POLICY_DRIFT medium; API_QUOTA_CONFIG_DRIFT low); 5-level risk model (none/low/medium/high/critical); config-signal gating requires topic prefix + file extension so generic source files are excluded; OpenAPI exclusion gates on root segment AND interior path for test/mock/fixture/example dirs (fixed after initial "check-after-match" bug); `isGraphQLSecurityConfig` user contribution point (GraphQL security tool names, apollo/graphql + security qualifier, Hasura/persisted-query detection, path-context gating); 190 tests; `apiSecurityDriftResults` schema table (2 indexes); `convex/apiSecurityDriftIntel.ts` (6 entrypoints: recordApiSecurityDriftScan/triggerApiSecurityDriftScan/getLatestApiSecurityDriftScan/getLatestApiSecurityDriftBySlug/getApiSecurityDriftScanHistory/getApiSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-64; `GET /api/repository/api-security-drift` HTTP route; `api.d.ts` registration; `RepositoryApiSecurityDriftPanel` dashboard component.
- WS-64 Database Security Configuration Drift Detector now complete: `convex/lib/databaseSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (POSTGRES_AUTH_CONFIG_DRIFT/MYSQL_AUTH_CONFIG_DRIFT critical; MONGO_AUTH_CONFIG_DRIFT/REDIS_AUTH_CONFIG_DRIFT/DATABASE_TLS_CONFIG_DRIFT/CONNECTION_POOL_CONFIG_DRIFT high; DB_MIGRATION_SECURITY_DRIFT/ELASTICSEARCH_SECURITY_DRIFT medium); 5-level risk model; migration detection uses prepended-slash trick to correctly match relative paths (e.g. `migrations/foo.sql` → `/migrations/foo.sql` contains `/migrations/`); parent-dir keyword check handles Prisma-style `add_auth_table/migration.sql`; `isDatabaseMigrationSecurityFile` user contribution point (security keywords in basename OR parent dir, restricted to recognised migration directories); 94 tests; `databaseSecurityDriftResults` schema table (2 indexes); `convex/databaseSecurityDriftIntel.ts` (6 entrypoints); fire-and-forget in events.ts before WS-63; `GET /api/repository/database-security` HTTP route; `api.d.ts` registration; `RepositoryDatabaseSecurityPanel` dashboard component.
- WS-63 Kubernetes & Container Security Hardening Drift Detector now complete: `convex/lib/containerHardeningDrift.ts` — pure library, 8 rules across 3 severity tiers (KUBE_RBAC_DRIFT critical; KUBE_NETWORK_POLICY_DRIFT/KUBE_POD_SECURITY_DRIFT/KUBE_ADMISSION_CONTROLLER_DRIFT/KUBE_EXTERNAL_SECRETS_DRIFT high; DOCKERFILE_HARDENING_DRIFT/CONTAINER_RUNTIME_POLICY_DRIFT/HELM_SECURITY_VALUES_DRIFT medium); 5-level risk model; extended vendor exclusion; k8s YAML detection (yaml/yml/json extensions with topic gating); HELM_SECURITY_TERMS gated on Helm directory to prevent k8s manifest false positives; `isKubeExternalSecretConfig` user contribution point (ExternalSecret/SecretStore/SealedSecret/CSI secrets/Vault operator detection); 100 tests; `containerHardeningDriftResults` schema table (criticalCount + highCount + mediumCount, 2 indexes); `convex/containerHardeningDriftIntel.ts` (6 entrypoints: recordContainerHardeningDriftScan/triggerContainerHardeningDriftScan/getLatestContainerHardeningDriftScan/getLatestContainerHardeningDriftBySlug/getContainerHardeningDriftScanHistory/getContainerHardeningDriftSummaryByTenant); fire-and-forget in events.ts before WS-62; `GET /api/repository/container-hardening` HTTP route; `api.d.ts` registration; `RepositoryContainerHardeningPanel` dashboard component.
- WS-62 Cloud Security Configuration Drift Detector now complete: `convex/lib/cloudSecurityDrift.ts` — pure library, 8 rules across 3 severity tiers (IAM_POLICY_DRIFT/KMS_KEY_POLICY_DRIFT critical; NETWORK_SECURITY_DRIFT/STORAGE_POLICY_DRIFT/API_GATEWAY_AUTH_DRIFT/SECRETS_BACKEND_DRIFT high; AUDIT_LOGGING_DRIFT/CDN_WAF_DRIFT medium); 5-level risk model (none/low/medium/high/critical); extended vendor dirs (.terraform/.cdk/cdk.out/__pycache__); config-signal gating (json/yaml/yml/tf/hcl/toml/conf/cfg/ini/env extensions only); `isAuditLoggingConfig` user contribution point (cloudtrail/stackdriver/azure-monitor/siem/log-analytics detection); 90 tests; `cloudSecurityDriftResults` schema table (criticalCount field, 2 indexes); `convex/cloudSecurityDriftIntel.ts` (6 entrypoints: recordCloudSecurityDriftScan/triggerCloudSecurityDriftScan/getLatestCloudSecurityDriftScan/getLatestCloudSecurityDriftBySlug/getCloudSecurityDriftScanHistory/getCloudSecurityDriftSummaryByTenant); fire-and-forget in events.ts before WS-61; `GET /api/repository/cloud-security-drift` HTTP route; `api.d.ts` registration; `RepositoryCloudSecurityDriftPanel` dashboard component.
- WS-61 Test Coverage Gap Detector for Security-Critical Code now complete: `convex/lib/testCoverageGap.ts` — pure library, 6 rules across 2 severity tiers (AUTH_CODE_UNTESTED/CRYPTO_CODE_UNTESTED/PAYMENT_CODE_UNTESTED high; AUTHZ_CODE_UNTESTED/SESSION_CODE_UNTESTED/SECURITY_MIDDLEWARE_UNTESTED medium); domain/test correlation via keyword sets + generic test file detection (`.test.`, `.spec.`, `test_*`, `*_test.*`, `__tests__/`, `/test/` segment); vendor exclusion; dedup-per-domain; `isSecurityMiddlewareSource` user contribution point; 92 tests; `testCoverageGapResults` schema table (2 indexes); `convex/testCoverageGapIntel.ts` (6 entrypoints: recordTestCoverageGapScan/triggerTestCoverageGapScan/getLatestTestCoverageGapScan/getLatestTestCoverageGapBySlug/getTestCoverageGapScanHistory/getTestCoverageGapSummaryByTenant); fire-and-forget in events.ts before WS-60; `GET /api/repository/test-coverage-gaps` HTTP route; `api.d.ts` registration; `RepositoryTestCoverageGapPanel` dashboard component.
- WS-60 Application Security Configuration Drift Detector now complete: `convex/lib/securityConfigDrift.ts` — pure library, 10 rules across 4 severity tiers (JWT_SECRET_CONFIG/ENCRYPTION_KEY_CONFIG critical; OAUTH_CLIENT_CONFIG/SAML_SSO_CONFIG/CORS_POLICY_CONFIG/CSP_HEADERS_CONFIG/TLS_OPTIONS_CONFIG high; SESSION_COOKIE_CONFIG/WAF_RULES_CONFIG medium; SECURITY_POLICY_CONFIG low); config-signal gating differentiates from WS-57 (security code) — requires `.config.*`/`Options`/`Policy`/`Rules` naming convention so plain `jwt.ts` utility files are excluded; TLS rule explicitly excludes actual certificate extensions (.pem/.crt/.key etc.) handled by WS-30/WS-54; dedup-per-rule with matchCount; 92 tests; `securityConfigDriftResults` schema table (2 indexes); `convex/securityConfigDriftIntel.ts` (6 entrypoints: recordSecurityConfigDriftScan/triggerSecurityConfigDriftScan/getLatestSecurityConfigDriftScan/getLatestSecurityConfigDriftBySlug/getSecurityConfigDriftScanHistory/getSecurityConfigDriftSummaryByTenant); fire-and-forget in events.ts before WS-59; `GET /api/repository/security-config-drift` HTTP route; `api.d.ts` registration; `RepositorySecurityConfigDriftPanel` dashboard component.
- WS-14 Phase 1 (Blast Radius Causality Graph foundation) complete: `convex/lib/blastRadius.ts` — pure computation library, `computeBlastRadius(input)` → `BlastRadiusResult` with reachableServices, exposedDataLayers, directExposureCount, transitiveExposureCount, attackPathDepth, businessImpactScore (spec formula: severity_weight×40 + directCap30 + exploit20 + transitive5bonus), summary, riskTier; `convex/lib/blastRadius.test.ts` — 19 tests covering no-components, direct-dep, transitive chain (depth 2/3), container (depth 3), multi-service blast, dedup, case-insensitive matching, risk tier boundaries, score cap; `schema.ts` — `blastRadiusSnapshots` table (findingId, repositoryId, tenantId, reachableServices, exposedDataLayers, directExposureCount, transitiveExposureCount, attackPathDepth, businessImpactScore, riskTier, summary, computedAt) with by_finding and by_repository_and_computed_at indexes; `convex/blastRadiusIntel.ts` — `computeAndStoreBlastRadius` internalMutation (loads finding+SBOM+disclosure, runs pure fn, patches finding, inserts snapshot), `getBlastRadius` public query, `blastRadiusSummaryForRepository` public query (maxRiskTier, totalReachableServices union, top 3 by score); `convex/events.ts` — `internal` import added, fire-and-forget `ctx.scheduler.runAfter(0, internal.blastRadiusIntel.computeAndStoreBlastRadius, { findingId })` wired into `ingestCanonicalDisclosure` after finding creation; `src/routes/index.tsx` — `FindingBlastRadiusPanel` per-finding sub-component (riskTier pill, reachableServices list, attackPathDepth, businessImpactScore), `RepositoryBlastRadiusSummary` per-repository aggregate (maxRiskTier, service count, top-3 findings) at top of each repository card

## Verified Status

- `bun run test --run` in `apps/web`: **8130/8130 passing (118 files)** — WS-42 enhancement complete (+65 tests)
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **5637/5637 passing (102 files)** — WS-79 complete

_Previous:_
- `bun run test --run` in `apps/web`: **5131/5131 passing (98 files)** — WS-75 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.56s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **4849/4849 passing (96 files)** — WS-73 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.44s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **4699/4699 passing (95 files)** — WS-72 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.43s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **4545/4545 passing (94 files)** — WS-71 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.35s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **4401/4401 passing (93 files)** — WS-70 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.35s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **4256/4256 passing (92 files)** — WS-69 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.36s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **4114/4114 passing (91 files)** — WS-68 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.34s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **4017/4017 passing (90 files)** — WS-67 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (4.92s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous (WS-66):_
- `bun run test --run` in `apps/web`: **3912/3912 passing (89 files)** — WS-66 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.37s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous (WS-65):_
- `bun run test --run` in `apps/web`: **3796/3796 passing (88 files)** — WS-65 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.23s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous (WS-64):_
- `bun run test --run` in `apps/web`: **3606/3606 passing (87 files)** — WS-64 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.56s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous (WS-61):_
- `bun run test --run` in `apps/web`: **3322/3322 passing (84 files)** — WS-61 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.49s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous (WS-60):_
- `bun run test --run` in `apps/web`: **3230/3230 passing (83 files)** — WS-60 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.67s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **3138/3138 passing (82 files)** — WS-59 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.55s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **3065/3065 passing (81 files)** — WS-58 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.54s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **2996/2996 passing (80 files)** — WS-57 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.36s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous:_
- `bun run test --run` in `apps/web`: **2911/2911 passing (79 files)** — WS-56 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.13s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous (WS-55):_
- `bun run test --run` in `apps/web`: **2823/2823 passing (78 files)** — WS-55 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.08s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous entry before that:_
- `bun run test --run` in `apps/web`: **2758/2758 passing (77 files)** — WS-54 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.20s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous entry before that:_
- `bun run test --run` in `apps/web`: **2692/2692 passing (76 files)** — WS-52 + WS-53 complete
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (1.07s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors

_Previous entries:_
- `bun run test --run` in `apps/web`: **2615/2615 passing (74 files)** — scoreProvenanceSignals implemented
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (55 modules, 1.70s)
- `bunx tsc --noEmit` in `apps/web`: 0 errors
- `bun run check` in `apps/web`: passing
- `bun run build` in `apps/web`: passing (55 modules, 497ms)
- `bun run test` in `apps/web`: passing (410 tests, 21 files; +30 webhookDispatcher)
- `bunx tsc --noEmit` in `apps/web`: passing (webhooks added to _generated/api.d.ts manually; next convex dev run will regenerate automatically)
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (55 modules, 736ms)
- `bunx tsc --noEmit` in `apps/web`: passing
- `bun run convex:codegen` in `apps/web`: passing
- `bun run check` in `apps/web`: passing (biome clean)
- `bun run build` in `apps/web`: passing (2075 modules)
- `bun run advisory:sync -- --tenant atlas-fintech --repository atlas-fintech/payments-api --hours 72`: not run yet because this is a live external-integration path we are deferring until final integration testing
- `bun run sbom:import -- . --dry-run --tenant atlas-fintech --repository atlas-fintech/operator-console --branch main --commit local-dryrun` in `apps/web`: passing
- `bun run sbom:import -- . --dry-run --tenant atlas-fintech --repository atlas-fintech/operator-console --branch main --commit lockfile-dryrun` in `apps/web`: passing
- `bun run sbom:import -- <temp-container-fixture> --dry-run --tenant atlas-fintech --repository atlas-fintech/operator-console --branch main --commit container-dryrun` in `apps/web`: passing
- `python -m compileall services\agent-core\src`: passing
- `python -m unittest discover -s tests` in `services\sbom-ingest`: passing
- `python -m compileall src` in `services\sbom-ingest`: passing
## Current Blockers

- Go is not installed on this machine yet, so Go service folders are architectural placeholders only
- GitHub webhook secret must be set as `GITHUB_WEBHOOK_SECRET` in the Convex deployment env before the first live webhook delivery can be exercised; use `npx convex env set GITHUB_WEBHOOK_SECRET <value>`
- GitHub token must be set as `GITHUB_TOKEN` in the Convex deployment env for the advisory sync live run and for the `proposeFix` action to open real PRs
- The webhook, advisory sync, semantic fingerprint, and exploit validation paths are all implemented locally, but the first fully live end-to-end repository scan still needs to be exercised against a real deployment and repository
- WS-11 PR generation is now complete including real manifest file editing; no known blockers remain for that workstream
- WS-13 is now fully complete: backend intelligence (scanner, supply chain analysis, Convex entrypoints), ingestion wiring (breach intake + webhook push), and dashboard panel (per-repository supply chain + injection scan panels) are all implemented and verified
- WS-14 Phase 1 (Blast Radius Causality Graph foundation) is complete: pure computation library + 19 unit tests, `blastRadiusSnapshots` schema table, `blastRadiusIntel.ts` Convex entrypoints, fire-and-forget wiring into `ingestCanonicalDisclosure`, `FindingBlastRadiusPanel` + `RepositoryBlastRadiusSummary` dashboard components. All checks green (144 tests, tsc, biome, build).
- WS-14 Phase 2 (Memory Controller + Red/Blue Loop MVP) is complete: `convex/lib/memoryController.ts` (pure aggregateFindingMemory, 17 tests), `convex/lib/redBlueSimulator.ts` (pure simulateAdversarialRound, 14 tests), `agentMemorySnapshots` + `redBlueRounds` schema tables, `convex/agentMemory.ts` (`refreshRepositoryMemory` internalMutation + `getRepositoryMemory` public query) and `convex/redBlueIntel.ts` (`runAdversarialRound` internalMutation, `runAdversarialRoundForRepository` public mutation, `getLatestRound` + `adversarialSummaryForRepository` public queries), fire-and-forget `refreshRepositoryMemory` wired into `ingestCanonicalDisclosure` after blast radius scheduling, `RepositoryMemoryPanel` + `AdversarialRoundPanel` dashboard components per repository card, "Run adversarial round" hero button. All checks green (175 tests, tsc, biome, build 2075+ modules).
- WS-14 Phase 3 (Attack Surface Reduction Agent MVP) is complete: `convex/lib/attackSurface.ts` (pure computeAttackSurface, score formula: remediationScore×50 + mitigationBonus + validationBonus + memoryHealthBonus + sbomBonus + noValidatedCriticalBonus, max=100; 29 tests), `attackSurfaceSnapshots` schema table, `convex/attackSurfaceIntel.ts` (`refreshAttackSurface` internalMutation, `refreshAttackSurfaceForRepository` public mutation, `getAttackSurfaceDashboard` combined query returning snapshot+history for sparkline), fire-and-forget `refreshAttackSurface` wired into `ingestCanonicalDisclosure`, `EMPTY_MEMORY_RECORD` exported from `memoryController.ts` (shared by redBlueIntel + attackSurfaceIntel), `RepositoryAttackSurfacePanel` dashboard component with score pill, trend pill, open critical/high counts, active PR pill, CSS-only sparkline. All checks green (204 tests, tsc, biome, build).
- WS-14 Phase 4 (Red Agent Finding Escalation) is complete: `convex/lib/redAgentEscalator.ts` (pure escalateRedAgentRound function; parses package-chain and depth-chain exploit chain formats, maps to FindingCandidate[] with severity/confidence/businessImpactScore/vulnClass/affectedPackages/affectedServices/blastRadiusSummary; 37 tests), `convex/redAgentEscalation.ts` (`escalateRedAgentFindings` internalMutation with dedupeKey idempotency guard + synthetic ingestionEvent + workflowRun + findings insertion; `getRedAgentFindingCount` public query), fire-and-forget `escalateRedAgentFindings` wired into `redBlueIntel.runAdversarialRound` on `roundOutcome === 'red_wins'`, `AdversarialRoundPanel` extended with `getRedAgentFindingCount` subscription + "N escalated findings" warning pill. All checks green (241 tests, tsc, biome, build).
- Security Posture Report is complete: `convex/lib/securityPosture.ts` (pure computeSecurityPosture; penalty model — findings cap 50, attack surface 0–25 by score tier, regulatory drift 0–20 by level, red agent 0–10 by win rate, learning maturity +0–5 bonus; 5-tier postureLevel; up to 4 topActions; 39 tests), `convex/securityPosture.ts` (getSecurityPostureReport query assembling findings/attackSurface/regulatoryDrift/redBlue/learningProfile/honeypot), `GET /api/reports/security-posture` HTTP endpoint in http.ts, `RepositoryPosturePanel` dashboard component at the top of each repository card. All checks green (380 tests, biome, build).
- WS-15 Phase 3 (Memory and Learning Loop) is complete: `convex/lib/learningLoop.ts` (pure computeLearningProfile; groups findings by normalised vuln class, calculates confirmed/FP counts, isRecurring when confirmed≥2, isSuppressed when FP rate>0.6, confidenceMultiplier 0.5–2.0; detects attack surface trend by comparing avg score of oldest vs newest half; adaptedConfidenceScore min(100, confirmed×5+rounds×3); collects unique exploit chains from red_wins rounds; 34 tests), `learningProfiles` schema table (vulnClassPatterns array + aggregates + successfulExploitPaths + trend + adaptedConfidenceScore + redAgentWinRate; indexed by_repository_and_computed_at), `convex/learningProfileIntel.ts` (3 entrypoints loading 500 findings + 100 rounds + 50 attack surface points), fire-and-forget wiring in events.ts as final post-ingestion step, `RepositoryLearningPanel` dashboard component. All checks green (341 tests, biome, build).
- WS-15 Phase 2 (Honeypot Code Auto-Injection) is complete: `convex/lib/honeypotInjector.ts` (pure computeHoneypotPlan; 8 endpoint templates, 4 DB field templates, 4 file templates, 2 token templates; affinity-scored against blast radius reachableServices+exposedDataLayers; depth bonus 5pts/level capped at 15; scores capped at 100; proposals sorted descending; 30 tests), `honeypotSnapshots` schema table (per-repo plan with per-kind counts, topAttractiveness, proposals array, summary; indexed by_repository_and_computed_at), `convex/honeypotIntel.ts` (`refreshHoneypotPlan` internalMutation aggregating blast radius across 50 snapshots + counting open criticals, `refreshHoneypotPlanForRepository` public mutation, `getLatestHoneypotPlan` public query), fire-and-forget wiring in `events.ts` after regulatory drift, `RepositoryHoneypotPanel` dashboard component (proposal count pills by kind, top-3 proposals by attractiveness with score pill + path, summary text). All checks green (307 tests, biome, build).
- Outbound Webhook System (spec §7.2) is complete: `convex/lib/webhookDispatcher.ts` (pure library — all 10 event types, HMAC-SHA256 signing via Web Crypto API, HTTP delivery, event filtering, URL/event validation; 30 tests), `webhookEndpoints` + `webhookDeliveries` schema tables (by_tenant, by_tenant_and_active, by_tenant_and_attempted_at, by_endpoint_and_attempted_at indexes), `convex/webhooks.ts` (registerEndpoint/deleteEndpoint/listEndpoints/listRecentDeliveries public entrypoints; queryActiveEndpoints internalQuery that returns secrets; recordDelivery internalMutation; dispatchWebhookEvent internalAction — fans out to all active subscribed endpoints, signs each payload, POSTs with X-Sentinel-Signature-256 header, records delivery audit row), HTTP endpoints: `POST/GET/DELETE /api/webhooks`, `GET /api/webhooks/deliveries` (all API-key-guarded in http.ts), fire-and-forget wiring for 5 event types: `finding.validated` (events.ts, after exploit validation patch), `finding.pr_opened` (prGeneration.ts, after recordPrOpened), `gate.blocked` (gateEnforcement.ts, evaluateGateForWorkflow), `gate.override` (gateEnforcement.ts, recordManualOverride), `regulatory.gap_detected` (regulatoryDriftIntel.ts, when criticalGapCount > 0), `attack_surface.increased` (attackSurfaceIntel.ts, when trend = degrading + previousSnapshot exists). All checks green (410 tests).
- WS-15 Phase 1 (Regulatory Drift Detection) is complete: `convex/lib/regulatoryDrift.ts` (pure computeRegulatoryDrift; VULN_CLASS_FRAMEWORKS mapping for SOC 2/GDPR/HIPAA/PCI-DSS/NIS2, severity penalties critical=20/high=12/medium=6/low=2/informational=0, validation multipliers validated=1.5/likely_exploitable=1.2, pr_opened 0.5× status multiplier, score floor at 0, drift levels compliant/drifting/at_risk/non_compliant; 36 tests), `regulatoryDriftSnapshots` schema table (per-framework score columns + overallDriftLevel + openGapCount + criticalGapCount + affectedFrameworks + summary + computedAt; indexed by_repository_and_computed_at), `convex/regulatoryDriftIntel.ts` (`refreshRegulatoryDrift` internalMutation loading up to 200 findings, `refreshRegulatoryDriftForRepository` public mutation with scheduler trigger, `getLatestRegulatoryDrift` public query), fire-and-forget `refreshRegulatoryDrift` wired into `events.ts` after attack surface refresh, `RepositoryRegulatoryDriftPanel` dashboard component with drift level pill, gap count pills, per-framework score pills (only drifting ones), summary text. All checks green (277 tests, biome, build).

- REST API completeness (spec §7.1) is now complete: all 24 spec-defined endpoints implemented across 28 HTTP routes in `http.ts`.
- Trust Score Computation Pipeline is now complete (this session): `convex/lib/componentTrustScore.ts` (pure library — 7-signal penalty model: known CVE -30, extra CVEs up to -20, direct-dep surcharge -5, typosquat -25, suspicious name -15, pre-release -8, unknown version -12; score clamped 0–100; 30 tests), `convex/trustScoreIntel.ts` (`refreshComponentTrustScores` internalMutation — batch-loads breach disclosures once, computes scores for all snapshot components, patches sbomComponents.trustScore + hasKnownVulnerabilities, dispatches trust_score.degraded when delta ≥ 10 and trust_score.compromised when score newly crosses below 30; `getRepositoryTrustScoreSummary` public query with 4-tier breakdown: trusted/acceptable/at_risk/compromised), fire-and-forget wiring in `sbom.ingestRepositoryInventory` (after snapshot creation) and `events.ingestCanonicalDisclosure` (after hasKnownVulnerabilities patch), `trust_score.compromised` type + data shape added to `webhookDispatcher.ts` — 11th spec §7.2 event type.
- Webhook event coverage (spec §7.2) is now **11/11 complete**: `finding.validated`, `finding.pr_opened`, `finding.resolved`, `trust_score.degraded`, `trust_score.compromised`, `honeypot.triggered`, `gate.blocked`, `gate.override`, `regulatory.gap_detected`, `sbom.drift_detected`, `attack_surface.increased`.
- WS-57 (Security Hotspot Change Detector) is complete: `convex/lib/highRiskChangeDetector.ts` (pure library: 12 rules across 6 categories — AUTH_HANDLER/TOKEN_MANAGEMENT/MFA_IMPLEMENTATION/CRYPTO_PRIMITIVE/PASSWORD_HANDLER/SIGNING_CODE/PAYMENT_PROCESSING/ADMIN_AREA/AUTHORIZATION_LOGIC/PII_HANDLING/RATE_LIMITER/SECURITY_MIDDLEWARE; deduplicated per rule — one finding per rule showing firstMatchedPath+matchCount; vendor-path exclusion for node_modules/dist/build/vendor/.yarn; same penalty/cap scoring as WS-52-56; 85 tests), `highRiskChangeResults` schema table (findings with matchCount field; 2 indexes), `convex/highRiskChangeIntel.ts` (6 entrypoints: recordHighRiskChangeScan/triggerHighRiskChangeScan/getLatestHighRiskChangeScan/getLatestHighRiskChangeScanBySlug/getHighRiskChangeScanHistory/getHighRiskChangeSummaryByTenant); fire-and-forget in events.ts after WS-56 git integrity block; `GET /api/repository/high-risk-changes` HTTP route; `api.d.ts` registration; `RepositoryHighRiskChangePanel` dashboard component (risk score pill + severity count pills + top-6 findings with rule label/category/matchCount/firstPath + recommendation text). All checks green (2996/2996 tests, 0 TS errors, biome clean, build 1.36s).

## Verified Status (Session 45)

- `bun run test --run` (apps/web): **2615/2615 passing** — 74 test files, all green (includes WS-51 securityTimeline 38 tests)
- `bun run check` (apps/web): **clean** — biome check passes 14 files with no errors
- `bun run build` (apps/web): **clean** — ✓ 5.36s client, ✓ 1.44s SSR
- `./node_modules/.bin/tsc --noEmit` (apps/web): **clean** — 0 TypeScript errors

## Verified Status (Session 44)

- `npx vitest run complianceRemediationPlanner` (apps/web): **79/79 passing** — WS-47 pure lib tests
- `npx vitest run licenseComplianceScanner` (apps/web): **91/91 passing** — WS-48 pure lib tests
- `npx vitest run repositoryHealthScore` (apps/web): **105/105 passing** — WS-49 pure lib tests
- `npx vitest run dependencyUpdateRecommendation` (apps/web): **68/68 passing** — WS-50 pure lib tests
- `./node_modules/.bin/tsc --noEmit` (apps/web): **clean** — 0 errors (after WS-47, WS-48, WS-49, and WS-50)

## What Was Built This Session (Session 45)

### WS-51 — Security Event Timeline

**`convex/lib/securityTimeline.ts` — pure computation library:**
- 14 event types: `finding_created`, `finding_escalated`, `finding_triaged`, `gate_blocked`, `gate_approved`, `gate_overridden`, `pr_opened`, `pr_merged`, `sla_breached`, `risk_accepted`, `risk_revoked`, `red_agent_win`, `auto_remediation_dispatched`, `secret_detected`
- `TimelineEntry` with `id`, `type`, `timestamp`, `title`, `detail`, `severity`, `metadata` (free-form extras)
- `buildSecurityTimeline(input, limit=50)` — maps each of 10 source arrays to `TimelineEntry[]`, merges, sorts newest-first, slices to `Math.min(limit, 100)`
- Filters: only `red_wins` rounds emit `red_agent_win`; only runs with `dispatchedCount > 0` emit `auto_remediation_dispatched`; only scans with `criticalCount + highCount > 0` emit `secret_detected`
- Dual events: `pr_opened` + optional `pr_merged` from one `prProposals` record; `risk_accepted` + optional `risk_revoked` from one `riskAcceptances` record
- `countTimelineEventsByType(entries[])` → `TimelineTypeCounts` (Record<type, number>)

**`convex/lib/securityTimeline.test.ts` — 38 tests, 38/38 first try**
- Covers: empty inputs, each event type, sorting, limit cap at 100, ID uniqueness, filtering, unknown severity → `undefined`

**`convex/securityTimelineIntel.ts` — 3 public queries:**
- Shared `loadTimelineData(ctx: QueryCtx, repositoryId)` helper — `Promise.all` across 10 tables (findings/severityEscalationEvents/findingTriageEvents/gateDecisions/prProposals/slaBreachEvents/riskAcceptances/redBlueRounds/autoRemediationRuns/secretScanResults); uses correct index per table
- `getSecurityTimelineForRepository` — slug-based, resolves tenant+repo, returns `buildSecurityTimeline(data, Math.min(limit, 100))`
- `getSecurityTimelineBySlug` — identical handler, alias for HTTP API callers
- `getTimelineEventCountsByType` — returns `countTimelineEventsByType(timeline)` for summary pills

**`convex/http.ts`** — `GET /api/security/timeline?tenantSlug=&repositoryFullName=&limit=50` endpoint (API-key-guarded, returns `{ timeline, count }`)

**`convex/_generated/api.d.ts`** — `securityTimelineIntel` + `lib/securityTimeline` registered

**`src/routes/index.tsx`** — `RepositorySecurityTimelinePanel` component:
- `TIMELINE_EVENT_ICON` map (14 types → emoji), `TIMELINE_SEVERITY_TONE` map, `formatRelativeTime(timestamp)` helper
- `useQuery(getSecurityTimelineForRepository, { tenantSlug, repositoryFullName, limit: 20 })`
- Summary pills row (finding_created / gate_blocked / sla_breached counts from `getTimelineEventCountsByType`)
- Vertical timeline list with connector line, icon, event title, detail text, severity pill, relative timestamp
- Self-hides when timeline is empty; wired after `RepositoryDependencyUpdatePanel`

## What Was Built This Session (Session 44)

### WS-47 — Compliance Gap Remediation Planner

**`convex/lib/complianceRemediationPlanner.ts` — pure computation library:**
- `REMEDIATION_CATALOG`: 22 entries (one per WS-46 control) each with ordered `PlaybookStep[]`, effort, estimatedDays, requiresPolicyDoc, evidenceNeeded[]
- `CONTROL_ROOT_CAUSE`: maps all 22 controlIds to 9 root cause strings (`secret_exposure`, `iac_misconfiguration`, `crypto_weakness`, `eol_or_cve`, `sbom_integrity`, `cicd_security`, `supply_chain_risk`, `container_risk`)
- `computeRemediationPlan(controlGaps[])` → `ComplianceRemediationPlan`: filters unknown controlIds; sorts by severity (critical→high→medium→low); deduplicates `estimatedTotalDays` via `Map<rootCause, maxDays>` then sum across distinct root causes
- `automatableActions`: count of actions with at least one automatable step

**`convex/lib/complianceRemediationPlanner.test.ts` — 79 tests, 79/79 first try** (after fixing missing `export` on `CONTROL_ROOT_CAUSE`)

**`schema.ts`** — `complianceRemediationSnapshots` table added (full `actions[]` with nested `steps[]`; 2 indexes)

**`convex/complianceRemediationIntel.ts`** — 5 entrypoints:
- `recordComplianceRemediationPlan` (internalMutation: reads latest `complianceAttestationResults` → flattens `controlGaps` from all frameworks → `computeRemediationPlan` → insert → prune to 30/repo; bails gracefully when no attestation exists)
- `triggerComplianceRemediationPlanForRepository` (public mutation — on-demand trigger)
- `getLatestComplianceRemediationPlan` (public query — most recent result)
- `getComplianceRemediationPlanHistory` (lean query — strips `steps` per action for trend display)
- `getComplianceRemediationPlanSummaryByTenant` (totalActions/totalCriticalActions/totalAutomatableActions/totalEstimatedDays + mostCriticalRepositoryId/mostCriticalActions)

**`sbom.ts`** — fire-and-forget `recordComplianceRemediationPlan` with `runAfter(7000)` delay (7s — after WS-46 at 5s)

**`http.ts`** — `GET /api/compliance/remediation-plan?tenantSlug=&repositoryFullName=`

**`_generated/api.d.ts`** — `complianceRemediationIntel` + `lib/complianceRemediationPlanner` registered

**`src/routes/index.tsx`** — `RepositoryRemediationPlanPanel`: critical/high/automatable count pills + `~Nd effort` pill; top-5 prioritised actions list showing title, controlId, gapSeverity pill, effort pill, policy doc indicator; `+N more actions` footer; self-hides when `totalActions === 0`; wired after `RepositoryCompliancePanel`

### WS-48 — License Compliance & Risk Scanner

**`convex/lib/licenseComplianceScanner.ts` — pure computation library:**
- `LICENSE_DATABASE`: 70 entries across permissive (MIT/Apache-2.0/ISC/…), weak_copyleft (LGPL-2.1/3.0, MPL-2.0, EPL-1/2, CDDL-1.0, …), strong_copyleft (GPL-2.0/3.0, AGPL-3.0, SSPL-1.0, OSL-3.0, EUPL-1.2, …), proprietary (BUSL-1.1, Elastic-2.0, …)
- `SPDX_ALIASES`: maps colloquial strings (GPLv2/GPLv3, "MIT License", "Apache 2.0") to canonical SPDX IDs; all keys lower-cased for case-insensitive matching
- `resolveCompoundLicense`: splits "MIT AND GPL-3.0" / "MIT OR GPL-3.0" / "Apache-2.0 WITH LLVM-exception" — takes worst risk component (conservative)
- `computeLicenseCompliance(components[])`: produces `LicenseComplianceResult` with per-package findings, licenseBreakdown (Record<spdxId, count>), overallRisk, unknownLicenseCount

**`convex/lib/licenseComplianceScanner.test.ts` — 91 tests, 91/91 first try** (after adding `export` to `SPDX_ALIASES`)

**`schema.ts`** — `licenseComplianceScanResults` table added (findings[] with full per-package fields including riskSignal union; `v.record(v.string(), v.number())` for licenseBreakdown; 2 indexes)

**`convex/licenseScanIntel.ts`** — 5 entrypoints:
- `recordLicenseComplianceScan` (internalMutation: reads latest `sbomSnapshots` → loads components via `by_snapshot` index → `computeLicenseCompliance` → insert → prune to 30/repo)
- `triggerLicenseComplianceScanForRepository` / `getLatestLicenseComplianceScan` / `getLicenseComplianceScanHistory` (lean — strips `description`) / `getLicenseComplianceScanSummaryByTenant`

**`sbom.ts`** — fire-and-forget with `runAfter(0)` immediately after WS-31 license compliance block

**`http.ts`** — `GET /api/sbom/license-scan?tenantSlug=&repositoryFullName=`

**`_generated/api.d.ts`** — `licenseScanIntel` + `lib/licenseComplianceScanner` registered

**`src/routes/index.tsx`** — `RepositoryLicenseScanPanel`: overallRisk pill + critical/high/unknown count pills + `N scanned` pill; top-5 per-package findings list (packageName + version + spdxId + licenseType label + riskLevel pill); `+N more findings` footer; self-hides when all riskLevels are 'none'; wired after `RepositoryLicenseCompliancePanel`

### WS-49 — Repository Security Health Score

**`convex/lib/repositoryHealthScore.ts` — pure computation library:**
- 7 weighted categories: `supply_chain` (25%), `vulnerability_management` (20%), `code_security` (15%), `compliance` (15%), `container_security` (10%), `license_risk` (10%), `sbom_quality` (5%)
- `CATEGORY_WEIGHTS`, `CATEGORY_LABELS`, `scoreToGrade` (A≥90/B≥75/C≥60/D≥40/F<40)
- Per-category penalty-based scorers with capped deductions: CVE critical -20/cap-60, CVE high -10/cap-30, EOL -15/cap-45, abandonment -15/cap-30, secret critical -20/cap-60, secret high -10/cap-30, crypto critical -15/cap-45, crypto high -8/cap-24, IaC -15/cap-30, CI/CD -15/cap-30, container critical -20/cap-60, container high -10/cap-30, license critical -20/cap-60, license high -10/cap-30, compliance non_compliant base 20, compliance at_risk base 55, compliance gaps -10/-5 capped
- Supply chain: uses `supplyChainScore` directly, overrides with `supplyChainRisk` critical→max(25) / high→max(50)
- SBOM quality: uses `sbomQualityScore` directly → falls back to grade mapping (excellent=100/good=80/fair=55/poor=25) → defaults 75
- `detectTrend(current, previous)`: improving (delta≥5), declining (delta≤-5), stable (|delta|<5), new (no previous)
- `computeRepositoryHealthScore(inputs: HealthScannerInputs) → RepositoryHealthReport`: weighted average, clamped 0–100, rounded; topRisks from lowest-scoring categories first (max 5); `buildSummary` with grade-A special case

**`convex/lib/repositoryHealthScore.test.ts` — 105 tests, 105/105 first try**

**`schema.ts`** — `repositoryHealthScoreResults` table added (overallScore/overallGrade/categories[]{category/label/score/weight/grade/signals[]}/trend/topRisks[]/summary/computedAt; 2 indexes)

**`convex/repositoryHealthIntel.ts`** — 5 entrypoints:
- `recordRepositoryHealthScore` (internalMutation: reads 12 scanner tables via `Promise.all` → builds `HealthScannerInputs` with previous score from same table → `computeRepositoryHealthScore` → insert → prune to 30/repo)
- `triggerRepositoryHealthScoreForRepository` (public mutation — on-demand trigger)
- `getLatestRepositoryHealthScore` (public query — most recent result)
- `getRepositoryHealthScoreHistory` (lean query — strips `signals` per category, trims `topRisks` to 3)
- `getRepositoryHealthScoreSummaryByTenant` (avgScore/gradeDistribution{A/B/C/D/F}/worstRepositoryId/worstScore/worstGrade/trendCounts{improving/declining/stable/new})

**`sbom.ts`** — fire-and-forget `recordRepositoryHealthScore` with `runAfter(9000)` delay (9s — after WS-47 at 7s, completing the cascade: WS-48@0s → WS-46@5s → WS-47@7s → WS-49@9s)

**`http.ts`** — `GET /api/repository/health-score?tenantSlug=&repositoryFullName=`

**`_generated/api.d.ts`** — `repositoryHealthIntel` + `lib/repositoryHealthScore` registered

**`src/routes/index.tsx`** — `RepositoryHealthScorePanel`: 4xl score/100 display + grade pill (A/B green, C yellow, D/F red) + trend pill (↑/↓/↔/• with success/danger/neutral tone); 7 mini category bars (color-coded: green≥90, yellow≥60, red<60 with label + score); top-3 risk bullets with danger-color dot; self-hides when grade A + stable/new + no risks; wired after `RepositoryRemediationPlanPanel`

### WS-50 — Dependency Update Recommendation Engine

**`convex/lib/dependencyUpdateRecommendation.ts` — pure computation library:**
- `parseSemver`: handles v-prefix, pre-release suffixes, Maven .RELEASE/.SNAPSHOT, 1-3 segment versions; returns `[major, minor, patch]` tuple or null
- `classifyEffort`: compares semver segments → patch/minor/major; unparseable defaults to major (safe assumption)
- `isMajorBump`: true if major segment increased; true for unparseable (assume breaking)
- `isReplacementPackage` heuristic: digit-only string = version number, letters present = different package name
- Deduplication: `Map<ecosystem::name, RecommendationBuilder>` with case-insensitive key; `Set<UpdateReason>` for combined reasons
- CVE processing: takes highest `minimumSafeVersion` across multiple CVEs for same package; adds all `cveIds`
- EOL processing: `end_of_life` → high urgency, `near_eol` → medium; `replacedBy` checked for package name vs version
- Abandonment processing: inherits `riskLevel` as urgency; `ABANDONMENT_LABEL` map for human-readable descriptions
- Sorting: urgency desc → effort asc (easiest first) → alphabetical tiebreak
- `computeUpdateRecommendations(input) → UpdateRecommendationResult` with criticalCount/highCount/patchCount/breakingCount/summary

**`convex/lib/dependencyUpdateRecommendation.test.ts` — 68 tests, 68/68 first try**

**`schema.ts`** — `dependencyUpdateRecommendations` table added (recommendations[] capped at 50 with full per-package fields; 2 indexes)

**`convex/dependencyUpdateIntel.ts`** — 5 entrypoints:
- `recordDependencyUpdateRecommendations` (internalMutation: reads latest from `cveVersionScanResults` + `eolDetectionResults` + `abandonmentScanResults` via `Promise.all` → maps findings to typed inputs → `computeUpdateRecommendations` → insert capped at 50 → prune to 30/repo; bails if no scanner results)
- `triggerDependencyUpdatesForRepository` / `getLatestDependencyUpdateRecommendations` / `getDependencyUpdateHistory` (lean — strips details/cveIds) / `getDependencyUpdateSummaryByTenant`

**`sbom.ts`** — fire-and-forget `recordDependencyUpdateRecommendations` with `runAfter(11000)` delay (11s — completing the full cascade: 0s → 5s → 7s → 9s → 11s)

**`http.ts`** — `GET /api/sbom/update-recommendations?tenantSlug=&repositoryFullName=`

**`_generated/api.d.ts`** — `dependencyUpdateIntel` + `lib/dependencyUpdateRecommendation` registered

**`src/routes/index.tsx`** — `RepositoryDependencyUpdatePanel`: critical/high/patch-level/breaking count pills; top-5 recommendations (packageName + currentVersion→recommendedVersion + migrate-to indicator + urgency pill + effort pill); `+N more updates` footer; self-hides when `totalRecommendations === 0`; wired after `RepositoryHealthScorePanel`

## Verified Status (Session 43)

- `npx vitest run complianceAttestationReport` (apps/web): **73/73 passing** — WS-46 pure lib tests
- `./node_modules/.bin/tsc --noEmit` (apps/web): **clean** — 0 errors

## What Was Built This Session (Session 43)

### WS-46 — Compliance Attestation Report Generator

**`convex/lib/complianceAttestationReport.ts` — pure computation library:**
- `COMPLIANCE_FRAMEWORKS`: `['soc2', 'gdpr', 'pci_dss', 'hipaa', 'nis2']`
- `GAP_PENALTIES`: critical=20 / high=12 / medium=6 / low=3 subtracted from 100 per framework
- `COMPLIANT_SCORE_THRESHOLD = 75`; `FRAMEWORK_LABELS` map
- 22 control-check functions: SOC2 (7 controls), GDPR (3), PCI-DSS (4), HIPAA (4), NIS2 (4)
- `computeComplianceAttestation(input)` → `ComplianceAttestationResult` with 5 `FrameworkAttestation` objects
- Framework status: `non_compliant` if criticalGaps>0; `at_risk` if highGaps>0 OR score<75; else `compliant`
- Overall status: worst of all 5 framework statuses

**`convex/lib/complianceAttestationReport.test.ts` — 73 tests, 73/73 first try**

**`schema.ts`** — `complianceAttestationResults` table added (2 indexes: `by_repository_and_computed_at`, `by_tenant_and_computed_at`)

**`convex/complianceAttestationIntel.ts`** — 5 entrypoints:
- `recordComplianceAttestation` (internalMutation: reads 12 scanner tables via `Promise.all` → builds `ComplianceAttestationInput` with safe defaults for missing data → `computeComplianceAttestation` → insert → prune to 30/repo)
- `triggerComplianceAttestationForRepository` (public mutation — on-demand trigger)
- `getLatestComplianceAttestation` (public query — most recent result)
- `getComplianceAttestationHistory` (lean query — strips `controlGaps` per framework for trend display)
- `getComplianceAttestationSummaryByTenant` (nonCompliantRepos/atRiskRepos/compliantRepos + totalCriticalGaps/totalHighGaps + worstRepositoryId/worstOverallStatus)

**`sbom.ts`** — fire-and-forget `recordComplianceAttestation` with `runAfter(5000)` delay (5s after container image scan — WS-46 block)

**`http.ts`** — `GET /api/compliance/attestation?tenantSlug=&repositoryFullName=`

**`_generated/api.d.ts`** — `complianceAttestationIntel` + `lib/complianceAttestationReport` registered

**`src/routes/index.tsx`** — `RepositoryCompliancePanel`: overall status pill + critical/high gap count pills + `N/5 compliant` pill; per-framework rows showing label, score, status pill, top-2 controlIds; self-hides when `overallStatus === 'compliant' && criticalGapCount === 0 && highGapCount === 0`; wired after `RepositoryContainerImagePanel`

## Verified Status (Session 42)

- `npx vitest run containerImageSecurity` (apps/web): **74/74 passing** — WS-45 pure lib tests
- `./node_modules/.bin/tsc --noEmit` (apps/web): **clean** — 0 errors

## What Was Built This Session (Session 42)

### WS-45 — Container Image Security Analyzer

**`convex/lib/containerImageSecurity.ts` — pure computation library:**
- `CONTAINER_IMAGE_DATABASE` (~45 entries: ubuntu 16.04/18.04/20.04, debian 9/10/11 + codenames, alpine 3.16–3.19, node 12/14/16/18/20 + erbium/fermium/gallium/hydrogen codenames, python 2/3.6–3.10, postgres 11–13, php 7/8.0/8.1, mysql 5.7/8.0, redis 5/6.0/6.2/7.0, nginx 1.20/1.22/1.24)
- Signals: `eol_base_image` (critical), `near_eol` (high, 90-day window), `outdated_base` (medium/low), `no_version_tag` (medium), `deprecated_image` (high/critical)
- `_IMAGE_INDEX` O(1) Map pre-built at module load
- `matchVersionPrefix` handles exact, `prefix-`, `prefix.`, `prefix_` — no substring false-positives
- `checkContainerImage` — ecosystem filter → unpinned check → DB lookup with registry-prefix stripping
- `computeContainerImageReport` — container-ecosystem filter, dedup by `ecosystem:name@version`, critical-first sort, aggregate counts + summary

**`convex/lib/containerImageSecurity.test.ts` — 74 tests, 74/74 first try**

**`schema.ts`** — `containerImageScanResults` table (2 indexes)

**`convex/containerImageIntel.ts`** — 5 entrypoints: `recordContainerImageScan` (internalMutation: load snapshot → load ≤500 components → computeContainerImageReport → insert → prune to 30/repo), `triggerContainerImageScanForRepository`, `getLatestContainerImageScan`, `getContainerImageScanHistory` (lean, no findings), `getContainerImageScanSummaryByTenant` (criticalRepos/highRepos/mediumRepos/lowRepos/cleanRepos + totalFindings + worstRepositoryId/OverallRisk)

**`sbom.ts`** — fire-and-forget `recordContainerImageScan` as final step in the chain (after posture score)

**`http.ts`** — `GET /api/sbom/container-image-scan?tenantSlug=&repositoryFullName=`

**`_generated/api.d.ts`** — `containerImageIntel` + `lib/containerImageSecurity` registered

**`src/routes/index.tsx`** — `RepositoryContainerImagePanel`: risk pill + images-scanned count pill + criticalCount/highCount/mediumCount pills; top-5 findings each showing `imageName:imageVersion` (monospace) + `→ recommendedVersion` + EOL date annotation + signal label pill; suppressed when `overallRisk === 'none'`; wired after `RepositorySupplyChainPosturePanel`

## Verified Status (Session 41)

- `npx vitest run supplyChainPostureScorer` (apps/web): **67/67 passing** — WS-44 pure lib tests
- `./node_modules/.bin/tsc --noEmit` (apps/web): **clean** — 0 errors

## What Was Built This Session (Session 41)

### WS-44 — Supply Chain Posture Score

**`convex/lib/supplyChainPostureScorer.ts` — pure computation library:**
- Penalty model with per-category caps: CVE (cap –50), Malicious (cap –50), Confusion (cap –40), Abandonment (cap –35), EOL (cap –25), Attestation (–20 tampered / –5 unverified or none)
- `scoreToGrade(score)` — A≥90 / B≥75 / C≥55 / D≥35 / F<35
- `scoreToRiskLevel(score, hasCritical, hasHigh)` — critical escalates on any critical-severity finding regardless of score
- `computeSupplyChainPosture(input)` — returns `{ score, grade, riskLevel, breakdown[], summary, cveRisk, maliciousRisk, confusionRisk, abandonmentRisk, eolRisk }`
- Input takes pre-shaped count summaries from each sub-scanner (decoupled from sub-scanner libraries)

**`convex/lib/supplyChainPostureScorer.test.ts` — 67 tests, 67/67 first try**

**`schema.ts`** — `supplyChainPostureScores` table

**`convex/supplyChainPostureIntel.ts`** — 5 entrypoints: `recordSupplyChainPosture` (internalMutation runs all 5 sub-scanners inline on the component list, loads attestation status, computes posture, inserts, prunes to 30/repo), `triggerSupplyChainPostureForRepository`, `getLatestSupplyChainPosture`, `getSupplyChainPostureHistory` (lean), `getSupplyChainPostureSummaryByTenant` (gradeA/B/C/D/F + averageScore + worstRepo)

**`sbom.ts`** — fire-and-forget `recordSupplyChainPosture` as final step in the chain (after CVE scan)

**`http.ts`** — `GET /api/sbom/supply-chain-posture?tenantSlug=&repositoryFullName=`

**`_generated/api.d.ts`** — `supplyChainPostureIntel` + `lib/supplyChainPostureScorer` registered

**`src/routes/index.tsx`** — `RepositorySupplyChainPosturePanel`: prominent 6xl A–F grade letter (color-coded) + score/100 + riskLevel pill; per-category breakdown chips showing `POSTURE_CATEGORY_LABEL[category]` + −penalty + detail text; summary text; suppressed when `riskLevel === 'clean'`; wired after `RepositoryCveScanPanel`

## Verified Status (Session 40)

- `npx vitest run cveVersionScanner` (apps/web): **50/50 passing** — WS-43 pure lib tests
- `./node_modules/.bin/tsc --noEmit` (apps/web): **clean** — 0 errors

## What Was Built This Session (Session 40)

### WS-43 — Known CVE Version Range Scanner

**`convex/lib/cveVersionScanner.ts` — pure computation library:**
- `KNOWN_CVE_DATABASE` — 30 CveEntry objects (17 npm, 6 maven, 7 pypi)
- `_CVE_INDEX` — Map pre-built at module load: `${ecosystem}:${name.toLowerCase()}` → `CveEntry[]`
- `parseVersionTuple(v)` — strips v-prefix, `.RELEASE`/`.SNAPSHOT`/`.BUILD-SNAPSHOT`/`.GA`, PyPI `a|alpha|b|beta|rc|.post|.dev` suffixes → `[major, minor, patch] | null`
- `compareVersionTuples(a, b)` — returns -1/0/1
- `isVersionVulnerable(installed, threshold)` — `boolean | null` (null = skip unparseable)
- `cvssToRiskLevel(cvss)` — ≥9.0=critical / ≥7.0=high / ≥4.0=medium / else=low
- `checkComponentCves(component)` — O(1) index lookup → `CveFinding[]`
- `computeCveReport(components[])` — ecosystem-lowercased dedup, CVSS-desc sort, summary, risk escalation

**`convex/lib/cveVersionScanner.test.ts` — 50 tests, 50/50 first try**

**`schema.ts`** — `cveVersionScanResults` table

**`convex/cveVersionScanIntel.ts`** — 5 entrypoints: `recordCveScan` (internalMutation: load snapshot → load ≤500 components → run report → cap 50 findings → insert → prune to 30/repo), `triggerCveScanForRepository` (mutation), `getLatestCveScan` (query), `getCveScanHistory` (lean query, no findings), `getCveSummaryByTenant` (surfaces `topCveId`/`topCvss`)

**`sbom.ts`** — fire-and-forget `recordCveScan` after malicious scan

**`http.ts`** — `GET /api/sbom/cve-scan?tenantSlug=&repositoryFullName=` (API-key-guarded)

**`_generated/api.d.ts`** — `cveVersionScanIntel` + `lib/cveVersionScanner` registered

**`src/routes/index.tsx`** — `RepositoryCveScanPanel`: risk pill + totalVulnerable/criticalCount/highCount/mediumCount pills; top-5 findings each showing CVE ID pill + CVSS score + "v{installed} → fix in v{safe}" annotation; suppressed when `overallRisk === 'none'`; wired after `RepositoryMaliciousScanPanel`

## Verified Status (Session 39)

- `npx vitest run maliciousPackageDetection` (apps/web): **55/55 passing** — WS-42 pure lib tests
- `./node_modules/.bin/tsc --noEmit` (apps/web): **clean** — 0 errors
- Prior baseline: 1861 tests (Session 37)

## What Was Built This Session (Session 39)

### WS-42 — Malicious Package Detection

**`convex/lib/maliciousPackageDetection.ts` — pure computation library:**
- `POPULAR_NPM_PACKAGES` — Set of ~80 top-100 npm packages (reference set for Levenshtein detection)
- `KNOWN_MALICIOUS_NPM_PACKAGES` — Map of 15 confirmed malicious/tyrosquat packages (crossenv/discordio/mongose/electorn/coffe-script/babelcli/event-streem/sqlite.js/lodahs/nodemailer-js/node-opencv2/htmlparser/base64js/discord-rpc2/axios2)
- `SQUATTING_SCOPES` — Set of 7 suspicious scope names (@npm/@node/@nodejs/@npms/@npmjs/@pkg/@packages)
- `TYPOSQUAT_EDIT_DISTANCE = 1`
- `levenshteinDistance(a, b)` — standard O(n·m) DP
- `findClosestPopularPackage(name, maxDistance?)` — length-guarded search; returns null if name IS popular
- `containsHomoglyphSubstitution(name)` — detects `[a-z]1[a-z]` (l/1 swap) and `[a-z]0[a-z]` (o/0 swap)
- `isNumericSuffixVariant(name)` — strips scope, checks popular-name + trailing-digits pattern
- `isScopeSquat(name)` — checks scope ∈ SQUATTING_SCOPES + bare name ∈ POPULAR_NPM_PACKAGES
- `checkMaliciousPackage(component)` — Signal 1 (known_malicious, npm-only) → critical/high; Signal 2 (typosquat_near_popular, unscoped npm-only, skipped if S1 fired) → high; Signal 3 (suspicious_name_pattern, all ecosystems, only when S1+S2 both skipped) → medium
- `computeMaliciousReport(components[])` — dedup by ecosystem.toLowerCase():name.toLowerCase()@version; findings sorted critical-first

**`convex/lib/maliciousPackageDetection.test.ts` — 55 tests, all passing**

**`schema.ts`** — `maliciousPackageScanResults` table

**`convex/maliciousPackageIntel.ts`** — 5 entrypoints

**`convex/sbom.ts`** — fire-and-forget `recordMaliciousScan` after confusion scan

**`convex/http.ts`** — `GET /api/sbom/malicious-scan`

**`convex/_generated/api.d.ts`** — `maliciousPackageIntel` + `lib/maliciousPackageDetection` registered

**`src/routes/index.tsx`** — `RepositoryMaliciousScanPanel` with per-signal badge chips and "Resembles: pkg" annotation; suppressed when clean; wired after `RepositoryConfusionScanPanel`

---

## Verified Status (Session 38)

- `npx vitest run confusionAttackDetection` (apps/web): **54/54 passing** — WS-41 pure lib tests
- `./node_modules/.bin/tsc --noEmit` (apps/web): **clean** — 0 errors including new `confusionAttackIntel.ts`
- Prior baseline: 1861 tests (63 Convex files) — Session 37

## What Was Built This Session (Session 38)

### WS-41 — Dependency Confusion Attack Detector

**`convex/lib/confusionAttackDetection.ts` — pure computation library:**
- `KNOWN_PUBLIC_NPM_SCOPES` — `Set<string>` of ~60 legitimate public npm scopes (babel/jest/types/aws-sdk/mui/angular/vue/react/stripe/prisma/convex-dev/etc.)
- `INTERNAL_NAME_PATTERNS` — 12 regexes: `internal-`/`-internal`, `private-`/`-private`, `corp-`/`-corp`, `company-`/`-company`, `enterprise-`/`-enterprise`, `intranet-`/`-intranet`
- `EXTREME_VERSION_THRESHOLD = 9000` / `HIGH_VERSION_THRESHOLD = 99` / `MEDIUM_VERSION_THRESHOLD = 49`
- `parseNpmScope(name)` — extracts `@scope` from scoped package, lowercased; null for unscoped
- `isKnownPublicNpmScope(scope)` — case-insensitive lookup in `KNOWN_PUBLIC_NPM_SCOPES`
- `parseMajorVersion(version)` — handles semver/v-prefix/partial; null for `latest`/`*`/unparseable
- `looksLikeInternalPackage(name)` — strips scope, tests bare name against all `INTERNAL_NAME_PATTERNS`
- `checkConfusionAttack(component)` → `ConfusionFinding | null` — three signals: `extreme_version` (major ≥9000, any ecosystem, always critical), `high_version_unknown_scope` (npm scoped + unknown scope + major ≥99, high if major ≥500 else medium), `high_version_internal_name` (name matches pattern + major ≥49, high if major ≥99 else medium)
- `computeConfusionReport(components[])` — dedup using `ecosystem.toLowerCase():name.toLowerCase()@version`, aggregate findings, `overallRisk` max-wins
- Fixed: `buildTitle` param renamed to `_riskLevel` (unused, TS6133)

**`convex/lib/confusionAttackDetection.test.ts` — 54 tests, all passing:**
- `parseNpmScope` ×6 / `isKnownPublicNpmScope` ×6 / `parseMajorVersion` ×6 / `looksLikeInternalPackage` ×6
- `checkConfusionAttack` ×15: null for normal/unparseable; extreme_version any-ecosystem; below-threshold negatives; high_version_unknown_scope npm-only; known-scope exception; non-npm exception; high_version_internal_name cross-ecosystem; below-MEDIUM negative; risk-level thresholds (≥500=high, <500=medium, ≥99=high); output shape (packageName/ecosystem/version/evidence/title)
- `computeConfusionReport` ×10: clean list/critical count/dedup/case-insensitive-ecosystem-dedup/escalation/high-only/summary/clean summary/empty/multi-finding
- `configuration constants` ×5: threshold ordering, KNOWN_PUBLIC_NPM_SCOPES required members, INTERNAL_NAME_PATTERNS type check

**`schema.ts` — new table:** `confusionAttackScanResults` (tenantId/repositoryId/totalSuspicious/criticalCount/highCount/mediumCount/lowCount/overallRisk union(critical|high|medium|low|none)/findings[]{packageName/ecosystem/version/signals[]/riskLevel/title/description/evidence}/summary/computedAt; indexes: `by_repository_and_computed_at`, `by_tenant_and_computed_at`)

**`convex/confusionAttackIntel.ts` — 5 entrypoints:**
- `recordConfusionScan` internalMutation — loads latest SBOM snapshot, ≤500 components, runs report, caps findings at 50, inserts row, prunes to 30 rows/repo
- `triggerConfusionScanForRepository` public mutation — on-demand by slug+fullName
- `getLatestConfusionScan` public query — latest result for a repository
- `getConfusionScanHistory` public query — last 30 lean summaries (findings stripped)
- `getConfusionSummaryByTenant` public query — criticalRepos/highRepos/mediumRepos/cleanRepos/totalSuspiciousPackages/mostRecentFlag/repoCount

**`convex/sbom.ts`** — fire-and-forget `recordConfusionScan` wired after attestation (WS-41 block)

**`convex/http.ts`** — `GET /api/sbom/confusion-scan?tenantSlug=&repositoryFullName=` (API-key-guarded)

**`convex/_generated/api.d.ts`** — `confusionAttackIntel` + `"lib/confusionAttackDetection"` registered

**`src/routes/index.tsx`** — `RepositoryConfusionScanPanel` per-repository component: overallRisk pill + totalSuspicious pill + per-severity count pills; top-5 findings list (mono package name + riskLevel pill + signal title); summary text at bottom; self-hides when `overallRisk === 'none'`; wired after `RepositoryAttestationPanel`

---

## Verified Status (Session 37)

- `npx vitest run` (apps/web): **1861 passing (63 Convex files)** — +35 tests from sbomAttestation (WS-40)
- `./node_modules/.bin/tsc --noEmit` (apps/web): **clean**
- `./node_modules/.bin/biome check` (apps/web): **clean**
- `bun run build` (apps/web): **clean** (55 modules, 168.84 kB index bundle)

## What Was Built This Session (Session 37)

### WS-40 — SBOM Attestation

**`convex/lib/sbomAttestation.ts` — pure computation library:**
- `sha256Hex(message)` — pure-JS FIPS 180-4 SHA-256 with `>>> 0` unsigned 32-bit arithmetic throughout; `Uint32Array` schedule extension; `TextEncoder` for UTF-8; verified against openssl/Python hashlib/Node.js crypto/sha256sum — SHA-256("") = `e3b0c4...`, SHA-256("abc") = `ba7816...`
- `ATTESTATION_VERSION = 1` — bump when canonicalization algorithm changes
- `canonicalizeSbomComponents(components[])` — lowercases ecosystem+name, format `ecosystem:name@version`, dedup via Set, lexicographic sort, prefix `sentinel-sbom-v1\n`
- `computeContentHash(components[])` — SHA-256 of canonical string (tenant-independent)
- `computeAttestationHash(contentHash, tenantSlug, snapshotId, capturedAt)` — SHA-256 of `contentHash:tenantSlug:snapshotId:capturedAt` (tenant-scoped)
- `generateSbomAttestation(snapshotId, components, tenantSlug, capturedAt, nowMs?)` → `AttestationRecord`
- `verifyAttestation(components, tenantSlug, snapshotId, capturedAt, storedHash, nowMs?)` → `VerificationResult` with `status: 'valid' | 'tampered'`, `integrityOk`, `storedHash`, `recomputedHash`, `verifiedAt`
- ⚠️ Test had wrong expected SHA-256 for "abc" (fabricated value `...2ec7...`); corrected to verified `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`

**`convex/lib/sbomAttestation.test.ts` — 35 tests:**
- `sha256Hex` ×7: empty string known-answer, "abc" known-answer, "hello world" length+regex+determinism, different inputs, always 64 chars, multi-block (64 chars), unicode
- `canonicalizeSbomComponents` ×7: sentinel prefix, order-independence, version sensitivity, deduplication, case-insensitivity, add component, empty list
- `computeContentHash` ×5: 64-char hex, deterministic, order-independent, version-sensitive, addition-sensitive
- `computeAttestationHash` ×4: 64-char hex, different tenants, different snapshots, different timestamps
- `generateSbomAttestation` ×5: valid record fields, hash lengths/regex, content≠attestation, deterministic, deduplicates componentCount
- `verifyAttestation` ×7: valid unchanged, tampered version, tampered removal, tampered addition, tampered wrong-tenant, verifiedAt timestamp, order-independent valid

**`schema.ts` — new table:** `sbomAttestationRecords` (tenantId/repositoryId/snapshotId/contentHash/attestationHash/componentCount/capturedAt/attestedAt/attestationVersion/status union(valid|tampered|unverified)/lastVerifiedAt?; indexes: `by_snapshot`, `by_repository_and_attested_at`, `by_tenant_and_attested_at`)

**`convex/sbomAttestationIntel.ts` — 6 entrypoints:**
- `recordSbomAttestation` internalMutation — loads latest snapshot, guards against duplicate-per-snapshot, loads up to 500 components, generates attestation, persists as `'unverified'`
- `verifySnapshotAttestation` internalMutation — reloads components, re-runs verifyAttestation, patches `status` + `lastVerifiedAt`
- `triggerAttestationForRepository` public mutation — on-demand by slug+fullName
- `getLatestAttestation` public query — latest for a repository
- `getAttestationBySnapshotId` public query — lookup by snapshotId
- `getAttestationSummaryByTenant` public query — valid/tampered/unverified counts + mostRecentTampered detail

**`convex/sbom.ts`** — fire-and-forget `recordSbomAttestation` wired as the final step after abandonment scan

**`convex/http.ts`** — `GET /api/sbom/attestation?tenantSlug=&repositoryFullName=` (API-key-guarded)

**`convex/_generated/api.d.ts`** — `sbomAttestationIntel` + `"lib/sbomAttestation"` registered

**`src/routes/index.tsx`** — `RepositoryAttestationPanel` per-repository component: status pill (✓ valid / ⚠️ tampered / ⏳ unverified) + componentCount pill + version pill; content hash + attestation hash hexdump cards; tampered warning message; lastVerifiedAt timestamp; self-hides when no attestation; wired after `RepositoryAbandonmentPanel`

---

## Verified Status (Session 36)

- `bunx vitest run` (apps/web): **1826 passing (62 Convex files)** — +46 tests from abandonmentDetection (WS-39)
- `bunx tsc --noEmit` (apps/web): **clean**
- `bunx biome check` (apps/web): **clean**
- `bun run build` (apps/web): **clean** (55 modules, 166.03 kB index bundle)

## What Was Built This Session (Session 36)

### WS-39 — Open-Source Package Abandonment Detector

**`convex/lib/abandonmentDetection.ts` — pure computation library:**
- `AbandonmentReason` union — `supply_chain_compromised | officially_deprecated | archived | superseded | unmaintained`
- `AbandonmentRisk` — `critical | high | medium | low`
- `ABANDONED_DATABASE` — 27 curated entries with version-prefix matching:
  - Critical (supply_chain_compromised): event-stream (Bitcoin wallet attack 2018), flatmap-stream (event-stream vector), ua-parser-js v0 (2021 npm compromise)
  - High (archived/unmaintained): request, phantomjs, phantomjs-prebuilt, pycrypto, cryptiles v3, therubyracer
  - Medium (officially_deprecated): tslint, node-sass, bower, karma, babel-polyfill, sklearn, nose
  - Low (superseded/unmaintained): node-uuid, popper.js, left-pad, istanbul, jshint, coffee-script, distribute, mock v1/v2, commons-logging 1.1, grunt v0, core-js v2
- `versionMatchesPrefix` — segment-safe prefix matching (reused from eolDetection, kept self-contained)
- `lookupAbandonedRecord` — case-insensitive, specificity-preferring sort (longer prefix wins, then higher risk)
- `checkPackageAbandonment` — generates title/description with reason-specific copy
- `classifyOverallRisk` — cascades from highest risk level present
- `computeAbandonmentReport` — deduplicates by ecosystem:name:version, counts per level, produces summary

**`convex/lib/abandonmentDetection.test.ts` — 46 tests:** versionMatchesPrefix ×6, lookupAbandonedRecord ×12, checkPackageAbandonment ×8, classifyOverallRisk ×5, computeAbandonmentReport ×11, ABANDONED_DATABASE integrity ×5

**`schema.ts` — new table:** `abandonmentScanResults` (tenantId/repositoryId/criticalCount/highCount/mediumCount/lowCount/totalAbandoned/overallRisk/findings[]/summary/computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)

**`convex/abandonmentScanIntel.ts` — Convex entrypoints:**
- `recordAbandonmentScan` internalMutation — loads latest SBOM snapshot + up to 500 components, runs computeAbandonmentReport, stores result, prunes to 30 per repo
- `triggerAbandonmentScanForRepository` public mutation — on-demand re-scan by slug+fullName
- `getLatestAbandonmentScan` public query — latest result resolved by slug+fullName
- `getAbandonmentScanHistory` lean query — last 30 summaries (findings stripped)
- `getAbandonmentSummaryByTenant` query — criticalRepos/highRepos/mediumRepos/lowRepos/cleanRepos/totalCriticalPackages/totalHighPackages/totalAbandonedPackages

**`convex/sbom.ts`** — fire-and-forget `recordAbandonmentScan` wired immediately after EOL scan scheduler call

**`convex/http.ts`** — `GET /api/abandonment/scan?tenantSlug=&repositoryFullName=` (API-key-guarded)

**`convex/_generated/api.d.ts`** — `abandonmentScanIntel` + `"lib/abandonmentDetection"` registered

**`src/routes/index.tsx`** — `RepositoryAbandonmentPanel` per-repository component: overall risk pill + criticalCount/highCount/mediumCount/lowCount pills + per-finding rows (reason emoji icon ☠️🚫📁🔄🕸️ + risk-level badge + package name + version mono chip + title + replacedBy hint); self-hides until first SBOM ingest; wired after `RepositoryEolPanel`

---

## Verified Status (Session 35)

- `bunx vitest run` (monorepo root): **1780 passing (61 Convex files)** — +46 tests from eolDetection (WS-38)
- `bunx tsc --noEmit` (monorepo root): **clean**
- `bun run check` (monorepo root): **clean** (biome)
- `bun run build` (monorepo root): **clean** (55 modules, 162.80 kB index bundle)

## What Was Built This Session (Session 35)

### WS-38 — Dependency & Runtime End-of-Life (EOL) Detection

**`convex/lib/eolDetection.ts` — pure computation library:**
- `NEAR_EOL_WINDOW_MS` — configurable 90-day near-EOL warning window
- `EOL_DATABASE` — static catalog of 33 EOL entries across runtimes (Node.js 10/12/14/16, Python 2.7/3.6/3.7/3.8, Ruby 2.7/3.0, PHP 7.4/8.0/8.1, .NET 5/6/7), frameworks (Django 1/2.2/3.2, Flask 1, Rails 5/6.0/6.1, Spring Boot 2.5/2.6, Log4j 1, Angular 12/13/14), and packages (request, node-uuid, core-js 2, jQuery 1/2)
- `versionMatchesPrefix` — segment-safe prefix matching ('14' matches '14.21.3', not '141.0')
- `parseVersionMajorMinor` — strips patch version for display ('14.21.3' → '14.21')
- `classifyEolStatus` — date-based: end_of_life / near_eol / supported / unknown
- `lookupEolEntry` — DB lookup with specificity-preferring sort (longer prefix wins)
- `checkComponentEol` — full single-component check with title/description generation
- `computeEolReport` — aggregates findings: dedupes by ecosystem:name:version, three-way null split (supported vs unknown), overallStatus critical/warning/ok, summary string

**`convex/lib/eolDetection.test.ts` — 46 tests:** versionMatchesPrefix ×6, parseVersionMajorMinor ×4, classifyEolStatus ×7, lookupEolEntry ×9, checkComponentEol ×8, computeEolReport ×9, EOL_DATABASE integrity ×3

**`schema.ts` — new table:** `eolDetectionResults` (tenantId/repositoryId/eolCount/nearEolCount/supportedCount/unknownCount/overallStatus/findings[]/summary/computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)

**`convex/eolDetectionIntel.ts` — Convex entrypoints:**
- `recordEolScan` internalMutation — loads latest SBOM snapshot + up to 500 components, runs computeEolReport, stores result, prunes to 30 per repo
- `triggerEolScanForRepository` public mutation — on-demand re-scan by slug+fullName
- `getLatestEolScan` public query — latest result resolved by slug+fullName
- `getEolScanHistory` lean query — last 30 summaries (findings stripped)
- `getEolSummaryByTenant` query — criticalRepos/warningRepos/okRepos/totalEolPackages/totalNearEolPackages

**`convex/sbom.ts`** — fire-and-forget `recordEolScan` wired as final step after SBOM quality scoring

**`convex/http.ts`** — `GET /api/eol/scan?tenantSlug=&repositoryFullName=` (API-key-guarded)

**`convex/_generated/api.d.ts`** — `eolDetectionIntel` + `"lib/eolDetection"` registered

**`src/routes/index.tsx`** — `RepositoryEolPanel` per-repository component: overallStatus pill + EOL/near-EOL/untracked count pills + per-finding rows (category icon + EOL status badge + package name + version mono chip + title + replacedBy hint); self-hides until first SBOM ingest; wired after `RepositoryCryptoWeaknessPanel`

---

## Verified Status (Session 34)

- `bunx vitest run` in `apps/web`: **1734 passing (60 Convex files)** — +61 tests from communityFingerprint (34) + cryptoWeakness (27)
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bun run check` in `apps/web`: **clean** (biome)
- `bun run build` in `apps/web`: **clean** (55 modules, 159.68 kB index bundle)

## What Was Built This Session (Session 34)

### WS-36 — Community Rule/Fingerprint Contribution Marketplace

**`convex/lib/communityFingerprint.ts` — pure computation library (spec §10 Phase 4):**
- `computeContributionScore` — netScore = upvotes−downvotes−reports×2; upvoteRatio; approvalEligible
- `isApprovalEligible` — skips operator decisions; checks score ≥ threshold and reports ≤ max
- `deriveStatus` — auto-escalates pending→under_review at REPORT_REVIEW_THRESHOLD; preserves approved/rejected
- `validateContribution` — title 5–120ch, description 20–2000ch, patternText 10–5000ch, vulnClass in known set of 19
- `summarizeMarketplaceStats` — counts by status/type, approved breakdowns by vulnClass and severity
- `rankContributions` — sort by netScore desc, createdAt tiebreak, immutable

**`convex/lib/communityFingerprint.test.ts` — 34 tests** covering all 6 functions

**`convex/communityMarketplace.ts` — Convex entrypoints:**
- `submitContribution` — validates then inserts with pending status
- `voteOnContribution` — idempotent vote switch; self-vote guard; by_voter_and_contribution dedup
- `reportContribution` — one-report-per-tenant; auto-transitions to under_review at threshold
- `approveContribution` / `rejectContribution` — internalMutations (operator use via dashboard)
- `listContributions` — type+status+vulnClass filters, net-score ranked, cap 200
- `getContributionDetail` / `getMarketplaceStats` / `getTopContributors` / `getApprovedByVulnClass` — queries

**`schema.ts` — new tables:** `communityContributions` + `contributionVotes` (already existed from previous session; no changes needed)

**`convex/http.ts` — routes:** `POST/GET /api/marketplace/contributions`, `POST /api/marketplace/contributions/vote`, `GET /api/marketplace/stats` (API-key-guarded)

**`convex/_generated/api.d.ts`:** `communityMarketplace` + `"lib/communityFingerprint"` registered

**Dashboard `CommunityMarketplacePanel`:**
- Approved/fingerprint/rule/pending/under-review count pills; top-5 approved by net score with type+vulnClass+severity+upvote pills
- Self-hides when totalContributions === 0; wired after `TenantGamificationPanel`

---

### WS-37 — Cryptography Weakness Detector

**`convex/lib/cryptoWeakness.ts` — pure computation library:**
- `detectSourceFileType(filename)` — maps 8 language extensions (py/js-family/java/go/rb/cs/php/rs)
- 16 rules covering broken hashes (MD5/SHA-1), broken ciphers (DES/RC4/Blowfish), insecure modes (ECB/CBC-no-MAC), weak randomness (near security context / seeded), weak password hashing, short RSA keys, TLS cert verification disabled, deprecated TLS versions, null cipher, base64 as encryption, hardcoded zero IV
- `scanFileForCryptoWeakness(filename, content)` → `CryptoScanResult`
- `combineCryptoResults(results[])` → `CryptoScanSummary`

**`convex/lib/cryptoWeakness.test.ts` — 61 tests** covering detectSourceFileType ×12, all 16 rules, unknown file type ×1, combineCryptoResults ×7

**`schema.ts` — new table:** `cryptoWeaknessResults` (tenantId/repositoryId/branch/commitSha/totalFiles/totalFindings/criticalCount/highCount/mediumCount/lowCount/overallRisk/fileResults[]/summary/computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)

**`convex/cryptoWeaknessIntel.ts` — Convex entrypoints:**
- `recordCryptoWeaknessScan` internalMutation — scans up to 10 files, cap 10 findings/file, inserts result, prunes to 50 per repo
- `triggerCryptoWeaknessScanForRepository` public mutation — resolves slug+fullName to IDs, schedules via scheduler
- `getLatestCryptoWeaknessScan` public query — slug+fullName resolver
- `getCryptoWeaknessScanHistory` lean query (fileResults stripped)
- `getCryptoWeaknessSummaryByTenant` — criticalRiskRepos/highRiskRepos/cleanRepos/totalFindings/repoCount

**`convex/events.ts` — wiring:**
- Fire-and-forget `recordCryptoWeaknessScan` filtering `.py|.js|.ts|.jsx|.tsx|.mjs|.cjs|.java|.go|.rb|.cs|.php|.rs` from changedFiles on every push

**`convex/http.ts`:** `GET /api/crypto/weaknesses?tenantSlug=&repositoryFullName=` (API-key-guarded)

**`convex/_generated/api.d.ts`:** `cryptoWeaknessIntel` + `"lib/cryptoWeakness"` registered

**Dashboard `RepositoryCryptoWeaknessPanel`:**
- Overall risk pill + totalFindings + critical/high/medium count pills + files-scanned pill
- Per-file rows: fileType badge + filename + inline findings (severity + title, up to 3 per file)
- Self-hides until first scan; wired after `RepositoryCicdScanPanel`

---

## Verified Status (Session 33)

- `bunx vitest run` in `apps/web`: **1673 passing (59 Convex files)** — +48 cicdSecurity tests (new file)
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bun run check` in `apps/web`: **clean** (biome)
- `bun run build` in `apps/web`: **clean** (55 modules, 156.50 kB index bundle)

## What Was Built This Session (Session 33)

### WS-35 — CI/CD Pipeline Security Scanner

**`convex/lib/cicdSecurity.ts` — pure computation library:**
- `detectCicdFileType(filename)` — infers CI/CD platform: `.github/workflows/*.yml`→github_actions, `.gitlab-ci.yml`→gitlab_ci, `.circleci/config.yml`→circleci, `bitbucket-pipelines.yml`→bitbucket_pipelines, else unknown
- 17 rules across 4 platforms + 2 cross-platform rules:
  - **GitHub Actions (6)**: GHACTIONS_SCRIPT_INJECTION/critical (event payload in run: step), GHACTIONS_PULL_REQUEST_TARGET/high, GHACTIONS_UNPINNED_ACTION/medium (tag vs SHA), GHACTIONS_EXCESSIVE_PERMISSIONS/high (write-all), GHACTIONS_SECRETS_IN_LOGGING/medium, GHACTIONS_SELF_HOSTED_RUNNER/medium
  - **GitLab CI (4)**: GITLAB_DIND_PRIVILEGED/critical, GITLAB_CURL_BASH_PIPE/high, GITLAB_ARTIFACT_NO_EXPIRY/low, GITLAB_UNVERIFIED_IMAGE/medium
  - **CircleCI (3)**: CIRCLE_CURL_BASH_PIPE/high, CIRCLE_MACHINE_LATEST_IMAGE/medium, CIRCLE_SSH_NO_FINGERPRINT/medium
  - **Bitbucket Pipelines (2)**: BB_PRIVILEGED_PIPELINE/critical, BB_CURL_BASH_PIPE/high
  - **Cross-platform (2)**: CI_INLINE_SECRET/high (hardcoded credential value), CI_MISSING_TIMEOUT/low (negated — fires when no timeout)
- `scanCicdFile(filename, content)` → `CicdScanResult`
- `combineCicdResults(results[])` → `CicdScanSummary` with overallRisk: critical/high/medium/low/none

**`convex/lib/cicdSecurity.test.ts` — 48 tests:**
- detectCicdFileType ×12, GitHub Actions rules ×9, GitLab CI rules ×5, CircleCI rules ×4, Bitbucket rules ×2, cross-platform ×5, unknown type ×1, combineCicdResults ×7
- Note: `${{` GitHub expressions escaped via `\x24` helper to prevent esbuild template-literal parse errors

**`schema.ts` — new table:**
- `cicdScanResults` (totalFiles, totalFindings, criticalCount/highCount/mediumCount/lowCount, overallRisk, fileResults[], summary, computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)

**`convex/cicdScanIntel.ts` — Convex entrypoints:**
- `recordCicdScan` internalMutation — scans up to 10 files (cap 10 findings/file), inserts result, prunes to 50 per repo
- `triggerCicdScanForRepository` public mutation — on-demand trigger with fileItems
- `getLatestCicdScan` public query
- `getCicdScanHistory` lean query (findings stripped)
- `getCicdScanSummaryByTenant` query — criticalRiskRepos / highRiskRepos / cleanRepos / totalFindings

**`convex/events.ts` — wiring:**
- Fire-and-forget `recordCicdScan` filtering `.github/workflows/*.yml|.gitlab-ci.yml|.circleci/config.yml|bitbucket-pipelines.yml` from changedFiles

**`convex/_generated/api.d.ts`:** `cicdScanIntel` + `"lib/cicdSecurity"` registered

**Dashboard `RepositoryCicdScanPanel`:**
- Overall risk pill + totalFindings + critical/high/medium count pills + files-scanned pill
- Per-file rows: platform badge (GH Actions / GitLab CI / CircleCI / Bitbucket) + filename + inline finding list (severity bracket + title, up to 3 per file)
- Self-hides until first scan; wired after `RepositoryIacScanPanel`

---

## Verified Status (Session 32)

- `bunx vitest run` in `apps/web`: **1625 passing (58 Convex files)** — +42 epssEnrichment tests (new file)
- `bunx tsc --noEmit` in `apps/web`: **clean** (also fixed pre-existing unused `scanned` var in iacSecurity.ts)
- `bun run check` in `apps/web`: **clean** (biome)
- `bun run build` in `apps/web`: **clean** (55 modules, 153.00 kB index bundle)

## What Was Built This Session (Session 32)

### WS-34 — EPSS Score Integration

**`convex/lib/epssEnrichment.ts` — pure computation library:**
- `classifyEpssRisk(score)` — critical ≥0.50 / high ≥0.20 / medium ≥0.05 / low <0.05
- `parseEpssApiResponse(json)` — FIRST.org v3 JSON parser; lenient status handling, clamped scores, CVE IDs normalised to uppercase, malformed entries skipped
- `extractCveIds(disclosures)` — collects deduplicated CVE IDs from `sourceRef` + `aliases`
- `buildEpssEnrichmentMap(entries)` — CVE-ID → EpssEntry Map (uppercase keys)
- `enrichDisclosureWithEpss(disclosure, epssMap)` — case-insensitive first-match lookup via sourceRef then aliases
- `buildEpssSummary(enriched, totalQueried)` — 4 risk-tier counts, avgScore, top-10 CVEs sorted desc, human-readable summary

**`convex/lib/epssEnrichment.test.ts` — 42 tests:**
- classifyEpssRisk ×10, parseEpssApiResponse ×9, extractCveIds ×6, buildEpssEnrichmentMap ×4, enrichDisclosureWithEpss ×6, buildEpssSummary ×7

**`schema.ts` — changes:**
- `breachDisclosures`: `epssScore: v.optional(v.number())` + `epssPercentile: v.optional(v.number())` (optional — old rows unaffected)
- New `epssSnapshots` table: syncedAt/queriedCveCount/enrichedCount/criticalRiskCount/highRiskCount/mediumRiskCount/lowRiskCount/avgScore/topCves[]/summary; `by_synced_at` index

**`convex/epssIntel.ts` — "use node" Convex module:**
- `syncEpssScores` internalAction — loads 500 recent disclosures, extracts CVE IDs, batches 100/request to FIRST.org API with per-batch fault isolation, patches disclosures in groups of 50, persists summary
- `getRecentDisclosuresForEpss` internalQuery
- `patchDisclosureEpss` internalMutation — batch-patch epssScore + epssPercentile
- `recordEpssSync` internalMutation — insert snapshot, prune to 30 rows
- `getLatestEpssSnapshot` public query
- `getEpssEnrichedDisclosures` public query — scored disclosures sorted by score desc, cap 200
- `triggerEpssSync` public mutation — on-demand scheduler trigger

**HTTP routes in `http.ts`:**
- `GET /api/threat-intel/epss` — latest snapshot + top-25 enriched disclosures (API-key-guarded)
- `POST /api/threat-intel/epss/sync` — manual sync trigger (API-key-guarded)

**`convex/crons.ts`:** daily `sync epss scores` cron at 04:00 UTC (after CISA KEV at 03:00)

**`convex/_generated/api.d.ts`:** `epssIntel` + `"lib/epssEnrichment"` registered

**Dashboard `EpssThreatIntelPanel`:**
- Sync stats: queriedCveCount / enrichedCount / critical-risk count / high-risk count / avg probability pills
- Top CVEs rows: risk-level pill + CVE ID (monospace) + exploit-probability pill + percentile pill + package·ecosystem label
- Self-hides until first sync; wired in JSX right after `ThreatIntelPanel`

---

## Verified Status (Session 31)

- `bunx vitest run` in `apps/web`: **1583 passing (57 Convex files)** — +46 iacSecurity tests (new file)
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bunx biome check src/routes/index.tsx` in `apps/web`: **clean**
- `bun run build` in `apps/web`: **clean** (55 modules, 149.07 kB index bundle)

## What Was Built This Session (Session 31)

### WS-33 — Infrastructure as Code (IaC) Security Scanner

**`convex/lib/iacSecurity.ts` — pure computation library:**
- `detectFileType(filename)` — infers IaC type: `.tf`→terraform, `docker-compose*`→compose, `Dockerfile*`→dockerfile, `.yaml/.yml`→kubernetes, `.json`→cloudformation, else unknown
- 20 rules with `{id, severity, title, description, remediation, fileTypes[], pattern, negated?}`:
  - **Terraform (6)**: TF_SG_OPEN_INGRESS/critical, TF_S3_PUBLIC_ACL/high, TF_RDS_PUBLIC/critical, TF_IAM_WILDCARD_ACTION/high, TF_IAM_WILDCARD_RESOURCE/high, TF_HTTP_LISTENER/medium
  - **Kubernetes (6)**: K8S_PRIVILEGED_CONTAINER/critical, K8S_HOST_NETWORK/high, K8S_HOST_PID/high, K8S_LATEST_IMAGE_TAG/medium, K8S_ALLOW_PRIVILEGE_ESCALATION/high, K8S_RUN_AS_ROOT/high
  - **Dockerfile (5)**: DOCKER_ROOT_USER/high (negated — fires when no USER found), DOCKER_ADD_COMMAND/medium, DOCKER_LATEST_TAG/medium, DOCKER_SENSITIVE_ENV/high, DOCKER_CURL_BASH_PIPE/high
  - **Compose (3)**: COMPOSE_PRIVILEGED/critical, COMPOSE_HOST_NETWORK/high, COMPOSE_SENSITIVE_ENV/medium
- `scanIacFile(filename, content)` → `IacScanResult`
- `combineIacResults(results[])` → `IacScanSummary` with overallRisk: critical/high/medium/low/none

**`convex/lib/iacSecurity.test.ts` — 46 tests:**
- detectFileType ×12, Terraform ×7, Kubernetes ×7, Dockerfile ×8, Compose ×4, unknown ×1, combineIacResults ×7

**`schema.ts` — new table:**
- `iacScanResults` (totalFiles, totalFindings, criticalCount/highCount/mediumCount/lowCount, overallRisk, fileResults[], summary, computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)

**`convex/iacScanIntel.ts` — Convex entrypoints:**
- `recordIacScan` internalMutation — scans up to 10 files (cap 10 findings/file), inserts result, prunes to 50 per repo
- `triggerIacScanForRepository` public mutation — on-demand trigger with fileItems
- `getLatestIacScan` public query
- `getIacScanHistory` lean query (findings stripped)
- `getIacScanSummaryByTenant` query — criticalRiskRepos / highRiskRepos / cleanRepos / totalFindings

**`convex/events.ts` — wiring:**
- Fire-and-forget `recordIacScan` filtering `\.tf$|\.ya?ml$|Dockerfile*|docker-compose` from changedFiles

**`convex/_generated/api.d.ts`:** `iacScanIntel` + `"lib/iacSecurity"` registered

**Dashboard `RepositoryIacScanPanel`:**
- Overall risk pill + totalFindings + critical/high/medium count pills + files-scanned pill
- Per-file rows: fileType badge + filename + inline finding list (severity bracket + title, up to 3 per file)
- Self-hides until first scan; wired after `RepositorySbomQualityPanel`

---

## Verified Status (Session 30)

- `bunx vitest run` in `apps/web`: **1537 passing (56 Convex files)** — +42 sbomQuality tests (new file); 5 pre-existing bun:test files from github-action/vscode-extension fail under vitest (not new)
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bunx biome check src/routes/index.tsx` in `apps/web`: **clean**
- `bun run build` in `apps/web`: **clean** (55 modules, 145.70 kB index bundle)

## What Was Built This Session (Session 30)

### WS-32 — SBOM Quality & Completeness Scoring

**`convex/lib/sbomQuality.ts` — pure computation library:**
- `isExactVersion(version)` — true when version contains no range specifiers (`^`, `~`, `>`, `<`, `=`, `*`, `|`); rejects empty / `any` / `latest`
- `computeFreshnessScore(capturedAt, now)` — linear decay: 100 at day 0, 0 at day 90+
- `countLayersPopulated(snapshot)` — counts non-zero entries across 6 SBOM layers (direct, transitive, build, container, runtime, AI model)
- `computeSbomQuality(snapshot, components, now?)` → `SbomQualityResult`
  - completenessScore = min(100, components×5) — reaches 100 at 20+ components
  - versionPinningScore = % of components with exact version pins (0% for empty SBOM, not vacuous 100%)
  - licenseResolutionScore = % of components with known licenses (0% for empty SBOM)
  - freshnessScore = max(0, 100 - daysSinceCapture×(100/90))
  - layerCoverageScore = (layersPopulated / 6) × 100
  - overallScore = weighted mean (completeness×0.25 + versionPinning×0.25 + licenseResolution×0.20 + freshness×0.15 + layerCoverage×0.15)
  - grade: excellent (≥80) / good (≥60) / fair (≥40) / poor (<40)
  - summary: natural-language issues list (unpinned versions, unknown licenses, stale snapshot, few layers)

**`convex/lib/sbomQuality.test.ts` — 42 tests:**
- isExactVersion ×12, computeFreshnessScore ×5, countLayersPopulated ×4, computeSbomQuality ×21

**`schema.ts` — new table:**
- `sbomQualitySnapshots` (overallScore, grade, 5 sub-scores, exactVersionCount, versionPinningRate, licensedCount, licenseResolutionRate, daysSinceCapture, layersPopulated, summary, computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)

**`convex/sbomQualityIntel.ts` — Convex entrypoints:**
- `computeAndStoreSbomQuality` internalMutation — loads latest sbomSnapshot + up to 500 sbomComponents, runs `computeSbomQuality`, inserts row, prunes to 30 per repo
- `triggerSbomQualityForRepository` public mutation — on-demand trigger; `Promise<void>` annotation breaks type cycle
- `getSbomQualityForRepository` public query — by tenantSlug + repositoryFullName
- `getSbomQualityHistory` lean query — last-N (all sub-scores included), capped at 30
- `getSbomQualitySummaryByTenant` query — dedupes latest per repo, returns totalRepositoriesScanned / excellentCount / goodCount / fairCount / poorCount / avgQualityScore

**`convex/sbom.ts` — wiring:**
- Fire-and-forget `computeAndStoreSbomQuality` after license compliance block in `ingestRepositoryInventory`

**`convex/_generated/api.d.ts`:** `sbomQualityIntel` + `"lib/sbomQuality"` registered

**Dashboard `RepositorySbomQualityPanel`:**
- Per-repository panel after `RepositoryLicenseCompliancePanel`
- Grade pill (excellent/good/fair/poor → success/info/warning/danger) + overall score/100 + component count + layers-populated/6
- Responsive 2–3 column grid of 5 sub-score cards (each shows sub-score name + colored score pill)
- Summary text; hides until first snapshot exists

---

## Verified Status (Session 29)

- `bunx vitest run` in `apps/web`: **1495/1495 passing (55 files)** — +44 licenseCompliance tests (new file)
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bunx biome check src/routes/index.tsx` in `apps/web`: **clean**
- `bun run build` in `apps/web`: **clean** (55 modules, 142.02 kB index bundle)

## What Was Built This Session (Session 29)

### WS-31 — Dependency License Compliance Engine

**`convex/lib/licenseCompliance.ts` — pure computation library:**
- `classifyLicense(spdx)` — 6 categories: permissive / weak_copyleft / strong_copyleft / network_copyleft / proprietary / unknown; SPDX OR/AND expression parsing (OR takes most permissive, AND takes most restrictive); case-insensitive; substring heuristics for AGPL/affero and GPL/LGPL natural-language strings
- `STATIC_DB` — 200+ well-known packages across npm (60+), pypi (40+), cargo (25+), go (15+) ecosystems
- `lookupStaticLicense(name, ecosystem)` — case-insensitive ecosystem lookup
- `assessComponentLicense(component, policy)` — static DB > provided `knownLicense` > unknown; source field: `static_db` / `provided` / `unknown`
- `DEFAULT_COMMERCIAL_POLICY` — permissive→allowed, weak_copyleft→warn, strong_copyleft→blocked, network_copyleft→blocked, proprietary→blocked, unknown→warn
- `computeLicenseCompliance(components, policy)` — score = `max(0, 100 - blocked×20 - warn×5)`; overallLevel: compliant / caution / non_compliant; violations[] capped at 20 per snapshot; natural-language summary

**`convex/lib/licenseCompliance.test.ts` — 44 tests:**
- classifyLicense ×18 (SPDX names, OR expressions, case-insensitivity, substring heuristics)
- lookupStaticLicense ×8 (npm/pypi/cargo/go; unknown package/ecosystem; case-insensitive)
- assessComponentLicense ×8 (static DB precedence, AGPL blocked, GPL blocked, LGPL warn, unknown warn, custom policy)
- computeLicenseCompliance ×10 (compliant/caution/non_compliant levels, score formula, score floor, empty list, unknown counts, allowedCount)

**`schema.ts` — new table:**
- `licenseComplianceSnapshots` (tenantId, repositoryId, snapshotId, totalComponents, blockedCount, warnCount, allowedCount, unknownCount, complianceScore, overallLevel, violations[], summary, computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)

**`convex/licenseComplianceIntel.ts` — Convex entrypoints:**
- `refreshLicenseCompliance` internalMutation — loads latest sbomSnapshot via `by_repository_and_captured_at` + up to 500 sbomComponents via `by_snapshot`, runs `computeLicenseCompliance`, inserts row, prunes to 30 per repo
- `refreshLicenseComplianceForRepository` public mutation — on-demand trigger by tenantSlug + repositoryFullName; `Promise<void>` annotation breaks TypeScript inference cycle
- `getLatestLicenseCompliance` public query — by tenantSlug + repositoryFullName
- `getLicenseComplianceHistory` lean query — last-N (violations stripped), capped at 30
- `getLicenseComplianceSummaryByTenant` query — dedupes latest per repo, returns totalRepositoriesScanned / nonCompliantCount / cautionCount / compliantCount / totalBlocked / totalWarn / avgComplianceScore

**`convex/sbom.ts` — wiring:**
- Fire-and-forget `refreshLicenseCompliance` in `ingestRepositoryInventory`, scheduled after HuggingFace enrichment block

**`convex/_generated/api.d.ts`:** `licenseComplianceIntel` + `"lib/licenseCompliance"` registered

**Dashboard `RepositoryLicenseCompliancePanel`:**
- Per-repository panel placed after `RepositorySecretScanPanel`
- Overall level pill (compliant/caution/non-compliant) + score/100 pill with color tier (green ≥80, yellow ≥50, red <50)
- Component count + blocked/warn/unknown count pills
- Violation rows: outcome badge (blocked/warn) + package name + ecosystem + resolved license + category
- Shows up to 5 violations, "+ N more" overflow line; self-hides until first snapshot exists

---

## Verified Status (Session 28)

- `bunx vitest run` in `apps/web`: **1451/1451 passing (54 files)** — +61 secretDetection tests (new file)
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bunx biome check src/routes/index.tsx` in `apps/web`: **clean**
- `bun run build` in `apps/web`: **clean** (55 modules, 138.67 kB index bundle)

## What Was Built This Session (Session 28)

### WS-30 — Hardcoded Credential & Secret Detection Engine

**`convex/lib/secretDetection.ts` — pure computation library:**
- `scanForSecrets(content, filename?)` — runs 19 regex detectors + entropy analysis on any content string
- 19 regex detectors across 10 families: AWS Access Key ID, AWS secret assignment, GCP service account JSON fragment, Azure Storage connection string, OpenAI API key (`sk-`), Anthropic API key (`sk-ant-api`), HuggingFace token (`hf_`), GitHub PAT/OAuth/Actions tokens (`ghp_`/`gho_`/`ghs_`), GitLab PAT (`glpat-`), Stripe live/test keys (`sk_live_`/`sk_test_`), SendGrid key (`SG.`), Slack bot token (`xoxb-`), RSA/EC/SSH/PGP private key PEM headers, PostgreSQL/MongoDB connection strings with credentials, hardcoded password assignment, generic API key assignment
- Shannon entropy analysis: quoted literals ≥ 16 chars with entropy ≥ 4.5 bits/char flagged as `high_entropy_string`; UUID and hex hash (MD5/SHA-1/SHA-256) exclusions prevent false positives
- `isLikelyPlaceholder` guard: `${...}`, `<...>`, `YOUR_`/`EXAMPLE_`/`REPLACE_ME` prefixes, `changeme`, `password123`, all-same-character strings, `xxxx...`, `dummy`/`fake`/`mock`/`sample` prefixes
- Quoted-value extraction for assignment patterns (e.g. extracts `changeme` from `password: "changeme"` before placeholder check)
- `isTestFile(filename)` — detects `.test.ts`, `.spec.ts`, `__tests__/`, `fixtures/`, `mocks/` paths → sets `isTestFileHint: true` on findings
- `redactMatch(match)` — first 4 + `***` + last 4 chars
- `combineResults(results[])` — aggregates multiple scan results

**`convex/lib/secretDetection.test.ts` — 61 tests**

**`schema.ts` — new table:**
- `secretScanResults` (tenantId, repositoryId, branch, commitSha?, scannedItems, findings[], criticalCount/highCount/mediumCount, totalFound, summary, computedAt; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)

**`convex/secretDetectionIntel.ts` — Convex entrypoints:**
- `recordSecretScan` internalMutation — scans a list of content items (content + optional filename), inserts combined result, prunes to 50 per repo
- `triggerSecretScanForRepository` public mutation — on-demand trigger by tenantSlug + repositoryFullName
- `getLatestSecretScan` public query — by tenantSlug + repositoryFullName
- `getSecretScanHistory` lean query — last-N, findings stripped
- `getSecretScanSummaryByTenant` query — dedupes latest scan per repo, returns affectedRepoCount + tenant-wide critical/high/medium totals

**`convex/events.ts` — wiring:**
- Fire-and-forget `recordSecretScan` in `ingestGithubPushForRepository`, scanning `changedFiles` list on every new push (no GitHub API call needed; changed file paths can expose secrets in directory/file names)

**`convex/_generated/api.d.ts`:** `secretDetectionIntel` + `"lib/secretDetection"` registered

**Dashboard `RepositorySecretScanPanel`:**
- Per-repository panel placed after `RepositoryTrafficAnomalyPanel`
- Clean/detected summary pill + severity breakdown pills + scanned-items pill
- Finding rows: severity badge + description + test-context hint badge + monospace redacted match
- Shows up to 5 findings, "+ N more" overflow line
- Self-hides until first scan result exists

---

## Verified Status (Session 27)

- `bunx vitest run` in `apps/web`: **1390/1390 passing (53 files)** — +40 trafficAnomaly tests (new file)
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bunx biome check src/routes/index.tsx` in `apps/web`: **clean**
- `bun run build` in `apps/web`: **clean** (55 modules, 135.77 kB index bundle)

## What Was Built This Session (Session 27)

### WS-29 — Production Traffic Anomaly Detection (spec §10 Phase 4)

**`convex/lib/trafficAnomaly.ts` — pure computation library:**
- 6 detection passes: `detectErrorSpike`, `detectPathEnumeration`, `detectSuspiciousUserAgent`, `detectLatencyOutliers`, `detectInjectionAttempts`, `detectRequestFlood`
- 14 attack-tool UA signatures (sqlmap, nikto, nuclei, gobuster, ffuf, hydra, etc.)
- 9 injection regex patterns (SQL/UNION/comment, path traversal, null byte, XSS, template injection, LFI, command injection)
- Combinatorial scoring: `anomalyScore = min(100, Σ confidence × PATTERN_WEIGHT[type])`; weights: injection_attempt=40, suspicious_user_agent=35, error_spike=25, path_enumeration=20, latency_outlier=20, request_flood=15
- 4-level classification: normal(<20) / suspicious(20–49) / anomalous(50–74) / critical(≥75)
- `computeTrafficAnomaly(events, baseline?)` → `TrafficAnomalyResult` with patterns, findingCandidates, stats, summary

**`convex/lib/trafficAnomaly.test.ts` — 40 tests:**
- All 6 detectors × 4–7 cases each; integration tests covering score calculation, level classification, finding candidate generation, empty event handling

**`schema.ts` — new table:**
- `trafficAnomalySnapshots` (anomalyScore, level, patterns array, findingCandidates array, stats object, summary; `by_repository_and_computed_at` + `by_tenant_and_computed_at` indexes)

**`convex/trafficAnomalyIntel.ts` — 3 public entrypoints:**
- `ingestTrafficEvents` public mutation — batch capped at 5000, computes anomaly, stores snapshot, prunes to 50 per repo; when anomalyScore ≥ 50 creates synthetic ingestionEvent + workflowRun + up to 3 findings
- `getLatestTrafficAnomaly` public query — by tenantSlug + repositoryFullName
- `getTrafficAnomalyHistory` lean query — last-N with leaderboards stripped

**`convex/http.ts` — new endpoint:**
- `POST /api/traffic/events?tenantSlug=&repositoryFullName=` (API-key-guarded, JSON array body)

**`convex/_generated/api.d.ts`:** `trafficAnomalyIntel` + `"lib/trafficAnomaly"` registered

**Dashboard `RepositoryTrafficAnomalyPanel`:**
- Per-repository panel placed after `RepositoryCloudBlastRadiusPanel`
- Level + score pills; request stats (total, error rate, avg latency, unique paths)
- Detected pattern rows with type badge + confidence + detail text
- Finding candidate severity pills with vuln class
- Summary text from pure library
- Self-hides until first ingestion

---

## Verified Status (Session 26)

- `bunx vitest run` in `apps/web`: **1350/1350 passing (52 files)** — +34 gamification tests (new file)
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bunx biome check src/routes/index.tsx` in `apps/web`: **clean**
- `bun run build` in `apps/web`: **clean** (55 modules, 132.92 kB index bundle)

## What Was Built This Session (Session 26)

### WS-28 — Gamification Layer (spec §3.7.4)

**`convex/lib/gamification.ts` — pure computation library:**
- `selectWindowSnapshots(snapshots, windowStart, windowEnd)` — boundary-inclusive window selector: `current` = latest in [start, end], `previous` = latest before start (baseline)
- `computeRepositoryLeaderboard(snapshots, prProposals, windowStart, windowEnd)` — groups snapshots by repositoryId, computes scoreDelta = current − previous, counts merged PRs within window, sorts by scoreDelta DESC (tie: currentScore DESC, name ASC), assigns gold/silver/bronze badges to ranks 1–3
- `computeEngineerLeaderboard(snapshots, prProposals, windowStart, windowEnd)` — groups merged PRs by `mergedBy` login, accumulates distinct repository names, sorts by mergedPrCount DESC (tie: login ASC)
- `computeGamification(snapshots, prProposals, windowDays=14, now)` — full sprint report: both leaderboards, totalScoreDelta, totalPrsMerged, mostImprovedRepository, summary sentence

**`convex/lib/gamification.test.ts` — 34 tests:**
- `selectWindowSnapshots` × 7: empty, latest in window, latest before window, no previous, no current, exact boundary inclusion (start + end)
- `computeRepositoryLeaderboard` × 12: empty, exclusion of no-data repos, in-window inclusion, zero-delta no-previous, positive/negative delta, multi-repo ranking, tie-breaking, gold/silver/bronze badge assignment, window-filtered PR count, open PR exclusion
- `computeEngineerLeaderboard` × 7: empty, no-mergedBy exclusion, outside-window exclusion, non-merged exclusion, multi-engineer ranking, alpha tie-break, multi-repo accumulation
- `computeGamification` × 8: empty/placeholder, windowDays/computedAt accuracy, totalScoreDelta, mostImprovedRepository, totalPrsMerged, summary top-performer, summary PR plural/singular, 30-day window

**`schema.ts` — two additions:**
- `gamificationSnapshots` table (repositoryLeaderboard and engineerLeaderboard arrays with full typed objects, mostImprovedRepository, totalScoreDelta/totalPrsMerged, summary, computedAt; `by_tenant_and_computed_at` index)
- `mergedBy: v.optional(v.string())` field added to `prProposals` (populated by `recordPrMergedBy` on GitHub PR-close webhook; optional so existing rows remain valid)

**`convex/gamificationIntel.ts` — Convex entrypoints:**
- `refreshGamification` internalMutation — loads repos by tenant, attack surface snapshots (2×windowDays lookback, 50 per repo), PR proposals (500 cap), runs computeGamification, inserts row, prunes to 20 per tenant
- `refreshAllTenantsGamification` internalMutation — zero-arg cron target, fans out to all active tenants (bounded at 200) via scheduler
- `refreshGamificationForTenant` public mutation — slug-based dashboard / on-demand trigger
- `getLatestGamification` public query — returns latest snapshot for a tenant by slug
- `getGamificationHistory` query — lean last-N history (windowDays/totals/summary, leaderboards stripped)
- `recordPrMergedBy` public mutation — called on GitHub `pull_request: closed+merged` webhook; matches by prNumber+repositoryId, patches mergedBy + mergedAt + status='merged'

**`convex/crons.ts` — new entry:**
- `'0 8 * * 1'` → `internal.gamificationIntel.refreshAllTenantsGamification` (Monday 08:00 UTC, before Slack/Teams digests)

**`convex/_generated/api.d.ts`:**
- `gamificationIntel` + `"lib/gamification"` registered

**Dashboard `TenantGamificationPanel`:**
- Tenant-level panel placed after `TenantVendorTrustPanel` in right column
- Stat pills: repos tracked, total score delta (green/red), security PRs merged
- Per-repository rows: badge emoji (🥇🥈🥉) or rank number, name, score pill, delta pill (green/red), trend pill, merged-PR count pill
- Engineer contributor pills when `engineerLeaderboard` has data
- Summary sentence from the pure library
- Self-hides when no snapshot exists yet

---

## Verified Status (Session 25)

- `bunx vitest run` in `apps/web`: **1280/1280 passing (50 files)** — unchanged
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bunx biome check src/routes/index.tsx` in `apps/web`: **clean**

## What Was Built This Session (Session 25)

### WS-27 dashboard surface — `TenantVendorTrustPanel`

**`convex/vendorTrust.ts` — `listVendorsBySlug` added:**
- Slug-based public query; resolves tenant via `by_slug` index, returns all vendors enriched with their latest risk snapshot (bounded at 100)
- Required because the dashboard never holds a raw `tenantId` — only `tenantSlug`

**`src/routes/index.tsx` — `TenantVendorTrustPanel` component:**
- Stat pills: active vendor count, critical/high risk counts, revoke/review recommendation counts
- Top-5 at-risk vendor rows (score ≥ 40, desc by riskScore): name, category badge, score pill, recommendation badge, scope-creep + breach-signal badges
- Self-hides when no vendors registered yet (null guard)
- Wired into the right-column `space-y-4` section directly after `TenantCrossRepoPanel`
- Lookup tables: `RISK_LEVEL_TONE`, `RECOMMENDATION_TONE`, `RECOMMENDATION_LABEL`, `CATEGORY_LABEL`

---

## Verified Status (Session 24)

- `vendorTrust` registered in `_generated/api.d.ts`
- `sweepAllTenantsVendorRisk` wired into `crons.ts` (daily 01:00 UTC)
- All prior checks from Session 23 remain valid (1280/1280 tests, tsc clean, biome clean)

## What Was Built This Session (Session 24)

### WS-27 — Vendor Trust & OAuth Risk (cron wiring + api.d.ts registration)

**`convex/vendorTrust.ts` — `sweepAllTenantsVendorRisk` appended:**
- Zero-arg `internalMutation` — queries all `active` tenants (bounded at 200)
- Fans out `sweepVendorRisk` per tenant via `ctx.scheduler.runAfter(0, ...)` — isolated failure/retry per tenant

**`convex/crons.ts` — new entry:**
- `'0 1 * * *'` → `internal.vendorTrust.sweepAllTenantsVendorRisk`
- Staggered before the 02:00 UTC auto-remediation dispatch; risk scores are fresh for the 09:00 Monday digests

**`convex/_generated/api.d.ts`:**
- `import type * as vendorTrust from "../vendorTrust.js"` added to imports
- `vendorTrust: typeof vendorTrust` added to `ApiFromModules` block

---

## Verified Status (Session 23)

- `bunx vitest run` in `apps/web`: **1280/1280 passing (50 files)** — +49 llmCertification tests
- `bunx biome check src/routes/index.tsx` in `apps/web`: **clean**

## What Was Built This Session (Session 23)

### WS-26 — LLM-Native Application Security Certification (spec §10 Phase 4)

**`convex/lib/llmCertification.ts` — pure computation library:**
- 7 certification domains: `prompt_injection`, `supply_chain_integrity`, `agentic_pipeline_safety`, `exploit_validation`, `regulatory_compliance`, `attack_surface`, `dependency_trust`
- `CertificationInput` type — pre-fetched snapshots from 7 source tables
- Per-domain evaluators: `evalPromptInjection`, `evalSupplyChainIntegrity`, `evalAgenticPipelineSafety`, `evalExploitValidation`, `evalRegulatoryCompliance`, `evalAttackSurface`, `evalDependencyTrust`
- `DOMAIN_WEIGHTS` (sum=100): prompt_injection=20, supply_chain_integrity=20, exploit_validation=20, agentic_pipeline_safety=15, attack_surface=10, regulatory_compliance=10, dependency_trust=5
- Critical domains: `prompt_injection` + `supply_chain_integrity` + `exploit_validation` — fail in any → Uncertified
- `computeCertificationTier(passCount, failedCriticalDomains, warnCount)` — customisable tier policy (default: 7 pass or 6+1warn→Gold; 4+ pass→Silver; 2+ pass→Bronze; else Uncertified)
- `computeCertificationResult(input)` → `CertificationResult` with tier, domainResults, passCount, warnCount, failCount, criticalFailedDomains, overallScore, summary

**`convex/lib/llmCertification.test.ts` — 49 tests:**
- `computeCertificationTier` (10): gold boundaries, silver, bronze, uncertified, critical failure blocking
- `prompt_injection` domain (5): clean pass, suspicious warn, confirmed/likely fail, null warn
- `supply_chain_integrity` domain (4): trusted pass, compromised fail, suspicious/at_risk warn
- `agentic_pipeline_safety` domain (4): no findings pass, critical fail, high/medium warn
- `exploit_validation` domain (4): passes, validated fail, likely fail, zero runs warn
- `regulatory_compliance` domain (4): compliant pass, non_compliant/at_risk fail, drifting warn
- `attack_surface` domain (4): pass, open critical fail, score<40 fail, moderate warn
- `dependency_trust` domain (4): pass, no components pass, low trust fail, moderate warn
- `computeCertificationResult` integration (10): gold, uncertified cases, silver/bronze, all-nulls, score bounds, domainResults count, summary text

**`convex/schema.ts` — `llmCertificationReports` table:**
- `tier` (gold/silver/bronze/uncertified), passCount, warnCount, failCount, overallScore
- `criticalFailedDomains` array, `domainResults` array (domain + outcome + score + rationale)
- Indexes: `by_repository_and_computed_at`, `by_tenant_and_computed_at`

**`convex/llmCertificationIntel.ts` — Convex entrypoints:**
- `refreshCertification` internalMutation — parallel fetch from 7 tables, SBOM trust aggregation, supply chain deduplication, exploit validation aggregation, inserts report, prunes to 20 per repo
- `refreshCertificationForRepository` public mutation — schedules internalMutation via `ctx.scheduler.runAfter(0, ...)`
- `getLatestCertificationReport` query — latest full report with domainResults
- `getCertificationHistory` query — last 10 reports, domainResults stripped (lean sparkline payload)
- `getTenantCertificationSummary` query — tier distribution + avgScore + certifiedCount

**Dashboard `RepositoryCertificationPanel`:**
- Shows at the TOP of each repository card (highest visibility — synthesis of all signals)
- Certification tier pill with emoji (🥇🥈🥉✗), overall score pill, pass/warn/fail count pills
- Domain breakdown table showing only failing/warning domains with rationale text
- Hidden until first report exists (null guard)
- All 7 domain labels localized in `DOMAIN_LABELS` map

## Verified Status (Session 22)

- `bunx vitest run` in `apps/web`: **1231/1231 passing (49 files)** — unchanged
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bunx biome check` in `apps/web`: **clean**
- `bun test` in `apps/vscode-extension`: **58/58 passing (4 files)** — +11 findPackageLine tests
- `PYTHONPATH=src python -m pytest tests/` in `services/agent-core`: **57/57 passing** — +33 agentic workflow tests

## What Was Built This Session (Session 22)

### WS-24 completion — `findPackageLine()` manifest resolver
- Per-format regex routing by `_fileName`: package.json/composer.json → JSON key pattern; requirements.txt → pip specifier; Pipfile/pyproject.toml → TOML key; go.mod → `name v` pattern; Cargo.toml → TOML key; pom.xml → `<artifactId>`; Gemfile → `gem 'name'`; generic fallback word boundary
- 11 new tests across package.json / requirements.txt / go.mod / Cargo.toml cases → 58/58 total

### WS-25 — Agentic Workflow Security Scanner (spec §10 Phase 4)

**`services/agent-core/src/sentinel_agent_core/analyzers/agentic_workflow.py`:**
- 7 vulnerability classes: `UNBOUNDED_LOOP` / `PRIVILEGE_ESCALATION` / `DATA_EXFILTRATION_CHAIN` / `TOOL_RESULT_INJECTION` / `MEMORY_POISONING` / `INSECURE_INTER_AGENT_COMM` / `UNVALIDATED_TOOL_OUTPUT`
- LangChain: `AgentExecutor`/`create_react_agent` without `max_iterations` → high
- CrewAI: `Process.hierarchical` → critical; `allow_delegation=True` → critical (import-line detection so standalone `Agent` files are caught)
- AutoGen: `GroupChat` → insecure_inter_agent_comm (medium); `code_execution_config={}` → privilege_escalation (critical)
- LlamaIndex: `AgentRunner`/`ReActAgent` without `max_steps` → high
- Cross-framework: memory store writes (`add_documents`/`save_context`/`upsert`) → memory_poisoning; read tool + send tool co-registration → data exfiltration chain
- Vercel AI SDK (TS): `generateText`/`streamText` with `tools:` but no `maxSteps:` → unbounded_loop; `execute: async` without TypeScript return annotation → unvalidated_tool_output
- `analyze_agentic_workflows(repo_path)` → `AgentWorkflowReport` with per-finding `evidence` + `remediation` guidance

**`services/agent-core/tests/test_agentic_workflow.py` — 33 tests:**
- `TestCleanRepo` (3), `TestLangChain` (5), `TestCrewAI` (4), `TestAutoGen` (3), `TestLlamaIndex` (2), `TestMemoryPoisoning` (3), `TestDataExfiltrationChain` (2), `TestVercelAiSdk` (3), `TestCounters` (5), `TestRemediation` (3)

**`services/agent-core/src/sentinel_agent_core/app.py` — upgraded to v0.3.0:**
- `AgenticWorkflowRequest` / `AgenticWorkflowResponse` / `AgenticFindingResponse` Pydantic models
- `POST /analyze/agentic-workflows` FastAPI endpoint
- `capabilities` list extended with `"agentic_workflow_security"`

**Convex `convex/agenticWorkflowIntel.ts`:**
- `persistAgenticScan` internalMutation — stores scan result rows
- `triggerAgenticScanForRepository` mutation — calls `AGENT_CORE_URL` + persists result
- `getLatestAgenticScan` query (with findings), `getAgenticScanHistory` query (aggregates only), `getTenantAgenticSummary` query (cross-repo rollup)

**`convex/schema.ts`:** `agenticWorkflowScans` table (findings[] array + counts + frameworksDetected; two indexes)

**Dashboard `RepositoryAgenticWorkflowPanel`:** critical/high/medium pills, framework list, per-finding cards with vulnClass + framework + evidence + file:line, files-scanned footer; wired after `RepositoryAutoRemediationPanel` per repository card

## Verified Status (Session 21)

- `bunx vitest run` in `apps/web`: **1231/1231 passing (49 files)** — unchanged
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bunx biome check` in `apps/web`: **clean**
- `bun test` in `apps/vscode-extension`: **47/47 passing (4 files)** — WS-24 new

## What Was Built This Session (Session 21)

### VS Code Extension — Phase 4 IDE Integration (WS-24, spec §10 Phase 4)

**`apps/vscode-extension/` — new app in the monorepo:**
- `package.json` — VS Code extension manifest: activationEvents for all 8 dependency manifest types, 5 commands (refresh/triggerScan/viewFindings/openDashboard/openFinding), 8 workspace settings (apiUrl/apiKey/tenantSlug/repositoryFullName/minSeverity/refreshIntervalSeconds/dashboardUrl/enableCodeLens), editor context menu item for manifest files
- `src/types.ts` — shared type definitions: `SentinelFinding`, `SentinelFindingsResponse`, `SentinelPostureReport`, `StoreSnapshot`, `ManifestMatch`; `SEVERITY_RANK`, `SEVERITY_TO_DIAGNOSTIC` lookup maps; `ALL_MANIFEST_BASENAMES` for file watching
- `src/config.ts` — `getConfig(vscode)` typed accessor + `isConfigured(config)` guard
- `src/sentinelClient.ts` — thin fetch-based REST API client: `getFindings()` (paginated, filtered by tenant+repo), `getPostureReport()` (graceful null on error), `triggerScan()` (fire-and-forget)
- `src/findingStore.ts` — observable singleton store: `subscribe(listener)` / `refresh()` / `startAutoRefresh()` / `dispose()`; all providers subscribe to one shared refresh cycle instead of making independent API calls; defensive snapshot copies
- `src/statusBarItem.ts` — `createStatusBarItem(vscode)`: posture score + level pill in VS Code status bar; red/amber/default background tiers; click opens findings panel; tooltip shows top actions
- `src/diagnosticsProvider.ts` — `createDiagnosticsProvider(vscode, minSeverity)`: per-file diagnostics from findings via `affectedPackages[]` → line scan with per-package regex; severity filter; excludes resolved/FP/ignored/accepted_risk
- `src/codeLensProvider.ts` — `createCodeLensProvider(vscode, getFindings)` + `buildCodeLensesForDocument` + `buildCodeLensTitle` + `groupFindingsByPackage` + `stripPackageName`; **`findPackageLine()` left as user contribution** (per-format manifest line resolver); `stripPackageName` correctly handles `npm:@babel/core`, `@babel/core@7.0.0`, `cargo:serde@1.0.0`
- `src/findingsPanel.ts` — `openFindingsPanel(vscode, context, snap, filterPackage?)`: dark-themed Webview panel with sortable findings table, posture score summary, PR buttons; handles "openUrl" messages to `vscode.env.openExternal`
- `src/commands.ts` — 5 command registrations: `sentinel.refresh`, `sentinel.triggerScan` (with 15s delayed re-fetch), `sentinel.viewFindings` (opens panel, passes filterPackage), `sentinel.openDashboard`, `sentinel.openFinding`
- `src/extension.ts` — `activate()` / `deactivate()` lifecycle: reads config, wires FindingStore → all providers, registers CodeLens for all manifest basenames, listens for document opens to re-run diagnostics, configuration change listener, starts auto-refresh if configured

**Tests (47 tests, 4 files):**
- `codeLens.test.ts` — 7 `stripPackageName` tests (unscoped/scoped/namespaced/version-stripped); 7 `groupFindingsByPackage` tests (single/version-stripped/scoped/merge/multi-pkg/empty/no-packages); 9 `buildCodeLensTitle` tests (empty/singular/plural/critical/high/combined/escalatedSeverity/validated badge/no badge); 1 `findPackageLine` placeholder test
- `sentinelClient.test.ts` — getFindings (5 tests: success/headers/query params/error/empty); getPostureReport (3 tests: success/404/network); URL construction (trailing slash stripping)
- `findingStore.test.ts` — initial state (1); refresh (5: load/lastRefreshedAt/isLoading lifecycle/error/error clear); subscribe (4: immediate delivery/notify on refresh/stop after unsub/defensive copy)
- `config.test.ts` — isConfigured (5: all present/missing each required field)

## What Was Built This Session (Session 20)

### Autonomous Remediation Dispatch — closes spec §3.18 (WS-23)

**Pure library `convex/lib/autoRemediation.ts`:**
- `AutoRemediationPolicy` type + `DEFAULT_AUTO_REMEDIATION_POLICY` (enabled=false opt-in, tierThreshold='p0', maxConcurrentPrs=3, allowedSeverities=['critical','high'])
- `AutoRemediationTierThreshold: 'p0' | 'p0_p1'`
- `AutoRemediationSkipReason: 'disabled' | 'concurrency_cap' | 'already_has_pr' | 'below_tier' | 'below_severity'`
- `isTierEligible(tier, threshold)` — p0 accepts only p0; p0_p1 accepts p0+p1
- `selectRemediationCandidates(queue, existingPrFindingIds, currentOpenPrCount, policy)` — returns `{ eligible, skipped, policyDisabled }`; `slotsRemaining = max(0, maxConcurrentPrs - currentOpenPrCount)`

**Tests `convex/lib/autoRemediation.test.ts` — 30 tests (new):**
- `isTierEligible`: 8 tests — p0/p0_p1 thresholds against all tier values
- `selectRemediationCandidates`: 22 tests — disabled policy (3), empty queue (1), already_has_pr (2), tier filtering (4), severity filtering (4), concurrency cap with currentOpenPrCount deduction (5), ordering (1), combined skip reasons (2)

**Schema `convex/schema.ts`:**
- Added `autoRemediationRuns` table: `repositoryId`, `tenantId`, `candidateCount`, `dispatchedCount`, `skippedAlreadyHasPr`, `skippedBelowTier`, `skippedBelowSeverity`, `skippedConcurrencyCap`, `dispatchedFindingIds[]`, `computedAt`
- Indexes: `by_repository_and_computed_at`, `by_tenant_and_computed_at`

**Convex entrypoints `convex/autoRemediationIntel.ts`:**
- `triggerAutoRemediationForRepository` internalMutation: short-circuits when policy disabled; builds priority queue inline (same signals as remediationQueueIntel: open+pr_opened findings, blast radius map, SLA assessment, exploit availability); loads open+draft prProposals for concurrency cap and existingPrFindingIds set; runs `selectRemediationCandidates`; schedules `api.prGeneration.proposeFix` fire-and-forget for each eligible finding (workflowRunId pulled from finding document); inserts `autoRemediationRuns` audit row
- `runAllAutoRemediationDispatches` internalMutation (cron target): fans out to all repositories
- `getAutoRemediationHistoryForRepository` query: by_repository_and_computed_at, desc, ≤50
- `getAutoRemediationSummaryBySlug` query: slug-based variant; aggregates across all runs

**Cron `convex/crons.ts`:**
- Added `auto remediation dispatch` daily at 02:00 UTC → `internal.autoRemediationIntel.runAllAutoRemediationDispatches`

**HTTP endpoint `convex/http.ts`:**
- `GET /api/remediation/auto-runs?tenantSlug=&repositoryFullName=` — API-key-guarded; returns aggregate summary or 404

**`convex/_generated/api.d.ts`:**
- Registered `autoRemediationIntel` + `lib/autoRemediation` (imports + fullApi entries)

**Dashboard `RepositoryAutoRemediationPanel` (`src/routes/index.tsx`):**
- Per-repository panel (takes `repositoryId`)
- Pills: dispatched count (success), candidate count, has-PR count, below-tier count, below-severity count, concurrency-cap count
- Recent 5 runs: dispatch count + candidate count pills, timestamp
- Hidden when no runs recorded
- Wired after `RepositoryEscalationPanel` in each repository card

## Verified Status (Session 19)

- `bunx vitest run` in `apps/web`: **1201/1201 passing (48 files)** — +66 escalationPolicy tests, +1 webhookDispatcher count update
- `bunx tsc --noEmit` in `apps/web`: **clean**
- `bunx biome check` in `apps/web`: **clean**

## What Was Built This Session (Session 19)

### Finding Severity Escalation Engine — closes spec §3.17 (WS-22)

**Pure library `convex/lib/escalationPolicy.ts`** (created previous session, tested this session):
- 5 escalation triggers: `exploit_available` (ceiling=critical), `blast_radius_critical` ≥80 (ceiling=high), `blast_radius_high` ≥60 (ceiling=medium), `cross_repo_spread` ≥threshold repos (ceiling=high), `sla_breach` (ceiling=medium)
- Severity ladder: informational(0) → low(1) → medium(2) → high(3) → critical(4)
- `getSeverityRank()`, `escalateSeverityForTrigger(current, trigger)` — +1 level from current up to trigger ceiling
- `assessEscalation(ctx, policy)` — collects active triggers, takes max proposed severity, strictly monotone (never decreases); informational/critical excluded
- `DEFAULT_ESCALATION_POLICY = { blastRadiusCriticalThreshold: 80, blastRadiusHighThreshold: 60, crossRepoSpreadThreshold: 3 }`

**Tests `convex/lib/escalationPolicy.test.ts` — 66 tests (new):**
- `getSeverityRank`: 6 tests — all 5 levels + ascending order invariant
- `escalateSeverityForTrigger`: ~15 tests — all 5 triggers, ceiling/at-ceiling/above-ceiling cases
- `assessEscalation`: 40 tests — boundary conditions (informational, critical, no triggers), all 5 single-trigger scenarios, multi-trigger resolution (max wins), rationale content (score/count embedded), custom policy thresholds

**Schema `convex/schema.ts`:**
- Added `severityEscalationEvents` table: `findingId`, `repositoryId`, `tenantId`, `previousSeverity`, `newSeverity`, `triggers[]`, `rationale[]`, `computedAt`
- Indexes: `by_finding`, `by_repository_and_computed_at`, `by_tenant_and_computed_at`

**Convex entrypoints `convex/escalationIntel.ts`:**
- `checkAndEscalateFinding` internalMutation: loads blast radius (by_finding, latest), exploit availability (breachDisclosure), cross-repo count (crossRepoImpactEvents by_source_finding), SLA status (assessSlaFinding); runs assessEscalation; if shouldEscalate → patches finding.severity + inserts severityEscalationEvents row atomically
- `runEscalationSweepForRepository` internalMutation: loads open+pr_opened findings (non-informational, non-critical), fans out `checkAndEscalateFinding` via scheduler.runAfter(0)
- `runAllEscalationSweeps` internalMutation (cron target): fans out to all repositories
- `getEscalationHistoryForFinding` query: audit log for one finding (desc, ≤50)
- `getEscalationSummaryForRepository` query: totalEscalations, uniqueFindingsEscalated, triggerCounts (per trigger), recentEvents (last 10)
- `getEscalationSummaryBySlug` query: slug-based variant for HTTP handler

**Webhook `convex/lib/webhookDispatcher.ts`:**
- Added 12th event type: `finding.severity_escalated`
- Added `FindingSeverityEscalatedData` type: `findingId`, `title`, `previousSeverity`, `newSeverity`, `triggers[]`, `rationale[]`
- Updated `ALL_WEBHOOK_EVENT_TYPES` array to 12 entries; updated dispatched union

**Cron `convex/crons.ts`:**
- Added `severity escalation sweep` every 4 hours → `internal.escalationIntel.runAllEscalationSweeps`

**HTTP endpoint `convex/http.ts`:**
- `GET /api/findings/escalations?tenantSlug=&repositoryFullName=` — API-key-guarded; returns escalation summary or 404

**Reactive wiring:**
- `convex/blastRadiusIntel.ts`: fire-and-forget `checkAndEscalateFinding` added after blast radius snapshot stored (reactive on businessImpactScore changes)
- `convex/crossRepoIntel.ts`: imported `internal`; fire-and-forget `checkAndEscalateFinding` added after upsert (reactive on affectedRepositoryCount changes)

**`convex/_generated/api.d.ts`:**
- Registered `escalationIntel` + `lib/escalationPolicy` (imports + fullApi entries)

**Dashboard `RepositoryEscalationPanel` (`src/routes/index.tsx`):**
- Per-repository panel (takes `repositoryId`)
- Pills: total upgrades (warning), unique findings (neutral), per-trigger counts (neutral, hidden when 0)
- Top 5 recent events: previous → new severity arrows, trigger pills, first rationale string
- Hidden when `totalEscalations === 0`
- Wired after `RepositoryRemediationQueuePanel` in each repository card

## Verified Status (Session 18)

- `bunx vitest run` in `apps/web`: **1135/1135 passing (47 files)** — +30 remediationPriority tests
- `bunx tsc --noEmit` in `apps/web`: **clean** (removed unused `ACTIVE_STATUSES` constant)
- `bunx biome check` in `apps/web`: **clean**

## What Was Built This Session (Session 18)

### Automated Remediation Priority Queue — closes spec §3.16 (WS-21)

**Pure library `convex/lib/remediationPriority.ts`:**
- Additive composite score: SLA breach +40, approaching +25, exploit available +20, validated/likely_exploitable +15, blast radius tiered +5/+10/+15 (≥20/≥50/≥80), severity tiered +2/+6/+10 (medium/high/critical); clamped at 100
- P0≥70 (immediate), P1≥45 (this sprint), P2≥20 (next sprint), P3<20 (backlog)
- `computeRemediationScore(candidate)` → `{ score, rationale[] }` — rationale is human-readable, ordered high-to-low weight
- `classifyPriorityTier(score)` → `'p0' | 'p1' | 'p2' | 'p3'`
- `prioritizeRemediationQueue(candidates[])` → `PrioritizedFinding[]` — sorted desc by score; tie-broken by `createdAt` asc (oldest unresolved first)
- `computeQueueSummary(queue)` → `{ totalCandidates, p0Count, p1Count, p2Count, p3Count, averageScore }`

**Tests `convex/lib/remediationPriority.test.ts` — 30 tests:**
- `computeRemediationScore`: 17 tests covering all signal combinations, max-out clamp at 100, rationale content
- `classifyPriorityTier`: 4 boundary tests
- `prioritizeRemediationQueue`: 6 tests — empty, sort order, tie-breaking, tier assignment, rationale presence, field preservation
- `computeQueueSummary`: 3 tests — empty, tier counts, average score

**Convex entrypoints `convex/remediationQueueIntel.ts`:**
- `getRemediationQueueForRepository` query: takes `repositoryId`, loads open+pr_opened+merged findings, excludes accepted-risk findings (via `riskAcceptances by_repository_and_created_at`), loads blast radius scores (Map pattern: desc order, first occurrence = most recent), loads breach disclosure exploit flags in-loop, returns `{ queue, summary }`
- `getRemediationQueueBySlug` query: slug-based variant (tenantSlug + repositoryFullName), returns `{ tenantSlug, repositoryFullName, queue, summary }` or `null`
- No new schema table — all data assembled on the fly from `findings`, `blastRadiusSnapshots`, `breachDisclosures`, `riskAcceptances`

**HTTP endpoint `convex/http.ts`:**
- `GET /api/remediation/queue?tenantSlug=&repositoryFullName=[&limit=25]` — API-key-guarded; limit capped at 100

**Dashboard `RepositoryRemediationQueuePanel` (`src/routes/index.tsx`):**
- Per-repository panel (takes `repositoryId`)
- Pills: P0×N (danger), P1×N (warning), P2×N (neutral), P3×N (neutral), avg score, total active count
- Top 5 findings in scored order: tier badge, severity badge, score badge, title, rationale string joined with ` · `
- Hidden when `totalCandidates === 0`
- Wired after `RepositoryRiskAcceptancePanel` in each repository card

**`convex/_generated/api.d.ts`:**
- `remediationQueueIntel` + `lib/remediationPriority` registered (imports + fullApi entries)

**`implementationTrack` updated:**
- "Automated remediation priority queue is live: every repository now has a composite-scored P0/P1/P2/P3 queue merging SLA breach, exploit availability, blast radius, and validation outcome; GET /api/remediation/queue"

## Verified Status (Session 17)

- `bun run test` in `apps/web`: **1105/1105 passing (46 files)** — +26 crossRepoImpact tests
- `bun run check` in `apps/web`: **biome clean**
- `bunx tsc --noEmit` in `apps/web`: **clean**

## What Was Built This Session (Session 17)

### Cross-Repository Impact Detection — closes spec §3.2.1 (lateral package exposure)

**Pure library `convex/lib/crossRepoImpact.ts`:**
- `normalizeForCrossRepo()`: lowercase → strip @scope/ → collapse separators; handles npm scoped packages, dots, underscores
- `matchesPackage()`: normalized name match + ecosystem comparison; ecosystem `unknown`/`''` → skip ecosystem check; uses pre-computed `normalizedName` field when available
- `assessRepositoryImpact()`: per-repo result with `directMatchCount`, `transitiveMatchCount`, `matchedVersions` (deduped), `affected` flag
- `computeCrossRepoImpact()`: maps all snapshots → impacts, filters affected, builds summary with "no lateral exposure" / "1 of N" / "N of M: repo-a, repo-b and K others" text
- 26 tests: `normalizeForCrossRepo`×5, `matchesPackage`×7, `assessRepositoryImpact`×6, `computeCrossRepoImpact`×8

**Schema `crossRepoImpactEvents` table:**
- Upserted by `(tenantId, normalizedPackageName)` — re-ingesting same advisory updates rather than duplicates
- `impacts[]` array with per-repo `repositoryId`/`repositoryName`/`directMatchCount`/`transitiveMatchCount`/`matchedVersions`
- Indexes: `by_source_finding`, `by_tenant_and_computed_at`, `by_tenant_and_normalized_package`

**Convex entrypoints `convex/crossRepoIntel.ts`:**
- `computeAndStoreCrossRepoImpact` internalMutation: loads all repos in tenant, excludes source repo, loads each repo's latest SBOM snapshot, computes impact, upserts result
- `getCrossRepoImpact` query: by source finding
- `getTenantCrossRepoSummary` query: N most recent events with `totalPackagesTracked`, `totalAffectedRepoSlots`, `packagesWithSpread`
- `getCrossRepoImpactBySlug` query: tenant slug + package name (HTTP handler pattern)
- `getTenantCrossRepoSummaryBySlug` query: tenant slug (dashboard panel)

**Fire-and-forget wiring in `convex/events.ts`:**
- Added after compliance evidence refresh in `ingestCanonicalDisclosure` (final post-ingestion step)
- Only wired when `affectedComponents.length > 0` (i.e., a finding was actually created)
- Args: `sourceFindingId`, `sourceRepositoryId`, `tenantId`, `packageName`, `ecosystem`, `severity`, `findingTitle`

**HTTP endpoint:**
- `GET /api/findings/cross-repo-impact?tenantSlug=<slug>&packageName=<name>` — API-key-guarded; returns single package impact record

**Dashboard `TenantCrossRepoPanel` (global — right column):**
- Shows total packages tracked, spread count, total repo exposure slots
- Per-package rows: severity pill, ecosystem pill, "N other repos" badge, repo names list
- Hidden when `totalPackagesTracked === 0`
- Wired as first item in right column (before "Breach intel aggregator")

**api.d.ts:** `crossRepoIntel` + `lib/crossRepoImpact` registered

## Verified Status (Session 16)

- `bun run test` in `apps/web`: **1079/1079 passing (45 files)** — +26 riskAcceptance tests
- `bun run check` in `apps/web`: **biome clean**
- `bun run build` in `apps/web`: **clean (105.41 kB index bundle)**
- `bunx tsc --noEmit` in `apps/web`: **clean**

## What Was Built This Session (Session 16)

### Risk Acceptance Lifecycle Engine — closes spec §4.3 (governed risk-accept)

**Pure library `convex/lib/riskAcceptance.ts`:**
- `isExpired()`: null → never expires; boundary-inclusive (nowMs >= expiresAt)
- `isExpiringSoon()`: configurable window (default 7d); false when already expired
- `formatExpiryText()`: 6-tier human-readable text (permanent / expired / expires today / expires tomorrow / expires in Nd)
- `computeExpiresAt()`: openedAt + durationDays * 24 * 3_600_000
- `computeAcceptanceSummary()`: only counts `active` records; permanent/temporary/expiringSoon/alreadyExpired buckets
- 26 tests

**Schema `riskAcceptances` table:**
- `by_status` index enables O(log n) expiry scan across all active acceptances
- `by_repository_and_created_at` for per-repo listing
- Level: `temporary` (bounded) | `permanent` (explicit revocation only)

**Convex entrypoints `convex/riskAcceptanceIntel.ts`:**
- `createRiskAcceptance` mutation: revokes any existing active acceptance first (clean transition), patches finding to `accepted_risk`
- `revokeRiskAcceptance` mutation: reverts finding to `open`
- `checkExpiredAcceptances` internalMutation: loads all active via `by_status`, transitions expired, re-opens findings, schedules Slack
- `getRiskAcceptancesBySlug` query (HTTP handler pattern)
- `getExpiringAcceptances` / `getAcceptanceSummaryForRepository` / `getActiveAcceptancesForTenant` queries

**Notification: `convex/slack.ts`:**
- `sendAcceptanceExpiryNotification` internalAction: expiry Block Kit with justification + approver

**Cron + HTTP + Dashboard:**
- Hourly `risk acceptance expiry check` cron
- `POST /api/findings/risk-accept`, `DELETE /api/findings/risk-accept`, `GET /api/findings/risk-acceptances`
- `RepositoryRiskAcceptancePanel` (hidden when no active acceptances; shows active count, expiring-soon badge, truncated justification list)

## Verified Status (Session 15)

- `bun run test` in `apps/web`: **1053/1053 passing (44 files)** — +32 slaPolicy tests
- `bun run check` in `apps/web`: **biome clean**
- `bun run build` in `apps/web`: **clean (103.40 kB index bundle)**
- `bunx tsc --noEmit` in `apps/web`: **clean**

## What Was Built This Session (Session 15)

### SLA Enforcement Engine — closes spec §3.13.3 (time-to-remediate accountability)

**Pure library `convex/lib/slaPolicy.ts`:**
- `DEFAULT_SLA_POLICY`: critical=24h, high=72h, medium=168h (7d), low=720h (30d)
- `assessSlaFinding()`: `not_applicable` (inactive/informational) → `within_sla` → `approaching_sla` (≥75% elapsed) → `breached_sla`
- `computeSlaSummary()`: complianceRate = (within + approaching) / totalTracked; MTTR = avg(resolvedAt−createdAt) for resolved findings
- 32 tests covering all status transitions, threshold mapping, MTTR edge cases

**Schema `slaBreachEvents` table:**
- Append-once per finding (deduped via `by_finding` index)
- Tracks `openedAt`, `breachedAt`, `notifiedAt`, `notificationChannels`

**Convex entrypoints `convex/slaIntel.ts`:**
- `checkSlaBreaches` internalMutation: loads open+pr_opened findings, inserts breach events, schedules Slack notification for first-time breaches
- `checkAllSlaBreaches` internalMutation: fans out to all repos via scheduler (one mutation per repo, independent transactions)
- `getSlaStatusForRepository` + `getSlaStatusBySlug` public queries
- `getSlaBreachHistory` + `getSlaComplianceReport` public queries
- `triggerSlaCheckForRepository` public mutation

**Notification: `convex/slack.ts`:**
- `sendSlaBreachNotification` internalAction: severity emoji + overdue hours Block Kit message; bypasses SLACK_MIN_SEVERITY filter

**Cron: `convex/crons.ts`:**
- `sla breach check` — `{ hours: 1 }` interval → `checkAllSlaBreaches`

**HTTP endpoint:**
- `GET /api/sla/status?tenantSlug=&repositoryFullName=` — API-key-guarded; returns assessments + summary

**Dashboard `RepositorySlaPanel`:**
- Compliance rate pill (green ≥90%, amber ≥70%, red <70%)
- Breach count badge (red if >0)
- Approaching count badge (amber if >0)
- MTTR pill
- Hidden when no active findings are tracked
- Wired after `RepositoryLearningPanel` in every repository card

**api.d.ts:** `slaIntel` + `lib/slaPolicy` registered

## Verified Status (Session 14)

- `bun run test` in `apps/web`: **1021/1021 passing (43 files)** — +25 findingTriage tests
- `bun run check` in `apps/web`: **biome clean**
- `bun run build` in `apps/web`: **clean**
- `bunx tsc --noEmit` in `apps/web`: **clean** — unused `Id` import removed from `findingTriage.ts`; `EvidenceFinding.status` + `FindingStatus` types updated for new statuses

## What Was Built This Session (Session 14)

### Analyst Feedback Loop — closes spec §3.13.2 analyst reinforcement path

**New statuses: `false_positive` and `ignored`:**
- `convex/schema.ts` — `findingStatus` union extended with `v.literal('false_positive')` and `v.literal('ignored')`; `findingTriageEvents` table added (3 indexes: `by_finding`, `by_repository_and_created_at`, `by_tenant_and_created_at`)
- `convex/findings.ts` — local validator updated
- `convex/lib/gatePolicy.ts` — `FindingStatus` type extended (`'false_positive' | 'ignored'`)
- `convex/lib/complianceEvidence.ts` — `EvidenceFinding.status` type extended
- `convex/http.ts` — `validStatuses` array updated; `PATCH /api/findings/triage` + `GET /api/findings/triage` routes added (both API-key-guarded)

**Pure library `convex/lib/findingTriage.ts`:**
- `TriageAction`: `'mark_false_positive' | 'mark_accepted_risk' | 'reopen' | 'add_note' | 'ignore'`
- `triageActionToStatus()`: maps actions to `FindingStatus`; `add_note` returns `null` (no status change)
- `computeTriageSummary()`: last-action-wins semantics; collects notes; `isFalsePositive` from last non-note action
- `analystFpRate()`: `falsePositiveCount / totalEvents` across summaries
- `analystConfidenceMultiplier()`: `1.0 - clamp(fpRate, 0, 1) * 0.75` — feeds back into learning loop penalty

**Convex entrypoints `convex/findingTriage.ts`:**
- `applyTriageAction` — unified public mutation: inserts triage event, patches status when applicable
- `markFalsePositive`, `reopenFinding`, `addTriageNote` — convenience wrappers
- `getTriageHistory` — events + `computeTriageSummary()` per finding
- `getFalsePositiveSummary` — per-repository FP count + breakdown by status
- `loadTriageEventsForLearningLoop` — internalQuery for 500 most recent triage events

**Learning loop integration (`convex/learningProfileIntel.ts`):**
- Single-line feedback: `validationStatus: f.status === 'false_positive' ? 'unexploitable' : f.validationStatus`
- Analyst-confirmed FPs override automated `validationStatus` before vuln-class grouping
- No extra DB queries; uses existing `findings` document status field

**Dashboard (`src/routes/index.tsx`):**
- `RepositoryLearningPanel` now accepts `repositoryId: Id<"repositories">` prop
- Subscribes to `getFalsePositiveSummary` per repository
- Renders FP count pill alongside maturity/trend metrics

**api.d.ts:** `findingTriage` + `lib/findingTriage` registered

**TypeScript fixes applied this session:**
- Removed unused `import type { Id }` from `findingTriage.ts` (TS6133)
- Updated `EvidenceFinding.status` in `lib/complianceEvidence.ts` (TS2322 in complianceEvidenceIntel.ts)
- Updated `FindingStatus` in `lib/gatePolicy.ts` (TS2322 in gateEnforcement.ts)

**Test count: 25 new tests → 1021/1021 total (43 files)**

## Verified Status (Session 13)

- `bun run test` in `apps/web`: **996/996 passing (42 files)** — +50 cisaKev + telegramIntel tests
- `bun run check` in `apps/web`: **biome clean**
- `bun run build` in `apps/web`: **clean (100.89 kB index bundle)**
- `bunx tsc --noEmit` in `apps/web`: **clean** — `convex/_generated/api.d.ts` updated manually to add `tier3Intel`, `lib/cisaKev`, `lib/telegramIntel`
- Python `uv run pytest` in `services/sandbox-manager`: **33/33 LLM injection tests passing**

## What Was Built This Session (Session 13)

### Tier 3 Threat Intelligence — closes all remaining roadmap "Later" items

**CISA KEV catalog integration:**
- `convex/lib/cisaKev.ts` — `parseCisaKevResponse` (validates CISA JSON shape, skips malformed entries, trims whitespace), `matchCisaKevToCveList` (case-insensitive CVE cross-ref), `cisaKevToSeverity` (ransomware→critical, overdue→critical, else→high), `buildCisaKevSummary` (totalEntries, ransomwareRelated, recentEntries, hasHighPriorityEntries); 26 tests
- `convex/lib/telegramIntel.ts` — CVE regex (`/CVE-\d{4}-\d{4,7}/gi`), credential patterns (GitHub PAT, AWS access keys, OpenAI keys, api_key), exploit keywords, ransomware group keywords, `parseTelegramPost`, `scoreMessageThreatLevel` (critical/high/medium/low/none scoring rubric); 24 tests
- `convex/tier3Intel.ts` — "use node" action module; `syncCisaKevCatalog` fetches CISA KEV, loads 500 breach disclosures, CVE cross-ref via in-memory Map, calls `markDisclosuresExploited` on matches; `handleTelegramUpdate` parses Bot API updates, stores non-none signals; `getBreachDisclosuresForKevMatch` (internalQuery — read-only); daily cron at 03:00 UTC; `triggerCisaKevSync` public mutation for on-demand runs

**HTTP routes:**
- `POST /webhooks/telegram` — `X-Telegram-Bot-Api-Secret-Token` guard; calls `handleTelegramUpdate`
- `GET /api/threat-intel/cisa-kev` — returns latest snapshot + high-priority signals (uses `api.tier3Intel.X`)
- `POST /api/threat-intel/cisa-kev/sync` — schedules sync on demand (uses `api.tier3Intel.X`)

**Key bug fixed:** Routes initially used `internal.tier3Intel.X` for public `query`/`mutation` functions — corrected to `api.tier3Intel.X` to match Convex routing contract

**Dashboard:**
- `ThreatIntelPanel` component — global (no per-repo context); shows CISA KEV snapshot (totalEntries, ransomwareRelated, matchedFindingCount, matched CVE pills, hasHighPriorityEntries), and last 5 critical/high Telegram signals with threatLevel/source/credential/ransomware pills; graceful "no sync yet" state; wired into right column after "Breach watchlist"

**api.d.ts:** `tier3Intel`, `lib/cisaKev`, `lib/telegramIntel` all registered

**TypeScript fix:** `cisaKev.test.ts` `makeEntry` type annotation simplified from complex conditional type to `Partial<CisaKevEntry>` (imported type)

## What Was Built This Session (Session 11)

### Multi-Cloud Blast Radius — closes spec §3.12 (AWS IAM + GCP + Azure resource graph)
- `convex/lib/cloudBlastRadius.ts` — pure library: `computeCloudBlastRadius`; maps 30 SDK packages to cloud resource types + sensitivity scores; formula: max_sensitivity + multi-provider +10 + IAM +15 + secrets +10 + data +5, clamped 0–100; 4 risk tiers; 4 risk flags; 27 tests
- SDK coverage: boto3/botocore/aws-sdk/@aws-sdk/client-* (12 AWS), @google-cloud/*+firebase-admin (9 GCP), @azure/*+azure-storage (7 Azure); prefix fallback for unrecognized SDK variants
- `convex/cloudBlastRadiusIntel.ts` — `computeAndStoreCloudBlastRadius` internalMutation + `getCloudBlastRadius` + `getCloudBlastRadiusBySlug` queries
- `schema.ts` — `cloudBlastRadiusSnapshots` table; fire-and-forget wired in `blastRadiusIntel.ts` (runs after every blast radius computation)
- `RepositoryCloudBlastRadiusPanel` — hides when no cloud SDK; shows risk tier/score/provider pills + IAM/data-exfil/secrets/lateral-movement flag pills + top-3 sensitive resources

### Microsoft Teams + Opsgenie alert integrations — closes spec §4.6.3 (notification coverage)
- `convex/lib/teamsCards.ts` — pure Adaptive Card builder: `buildTeamsPayload()`, `severityToColor()`, `meetsMinSeverity()`; 3 alert kinds (finding_validated / gate_blocked / honeypot_triggered); 29 tests
- `convex/teams.ts` — `sendTeamsAlert` internalAction + `recordTeamsDelivery` + `sendWeeklyTeamsDigest` + `listRepoSummariesBySlug` internalQuery; `TEAMS_WEBHOOK_URL`, `TEAMS_MIN_SEVERITY` env vars; Monday 09:15 UTC digest cron
- `convex/lib/opsgeniePayload.ts` — pure payload builder: `buildCreateAlertBody`, `buildCloseAlertBody`, `buildOpsgenieAlias`, `sentinelSeverityToOpsgenieP`; 24 tests
- `convex/opsgenie.ts` — `sendOpsgenieAlert`, `pageOnConfirmedExploit`, `pageOnHoneypotTrigger`, `resolveOpsgenieAlert`; `OPSGENIE_API_KEY`, `OPSGENIE_TEAM_ID`, `OPSGENIE_SEVERITY_THRESHOLD` env vars
- Both modules fire-and-forget wired into events.ts (finding_validated), gateEnforcement.ts (gate_blocked), honeypotIntel.ts (honeypot_triggered)
- Registered in `convex/_generated/api.d.ts` (`teams`, `opsgenie`, `lib/teamsCards`, `lib/opsgeniePayload`)

### LLM Injection Module — closes spec §3.9 / §3.4.2 (Full LLM Sandbox Testing)
- `services/sandbox-manager/src/sentinel_sandbox/exploits/llm_injection.py` — `LlmInjectionModule`: 8 payloads × 6 AI endpoint paths × 3 body formats = **144 attempts per finding**
- Canary-based detection: payloads embed unique phrases (`SENTINEL_CANARY_4829`, `SENTINEL_CANARY_7163`, `TOOL_INJECTED_8521`, `SENTINEL_RAG_PWNED`) that only appear in responses if injection succeeded
- Payload types: direct canary, role-switch canary, system prompt leak (direct + indirect), jailbreak DAN, override jailbreak, tool result injection, RAG context injection
- Body formats: OpenAI-compatible `{"messages": [...]}`, simple `{"message": "..."}`, generic `{"prompt": "...","input": "..."}`
- Endpoint paths: `/v1/chat/completions`, `/api/chat`, `/api/generate`, `/chat`, `/api/ask`, `/api/complete`
- `models.py` — `LLM_INJECTION = "llm_injection"` added to `ExploitCategory`; `executor.py` — module registered + `DEFINITIVE` set extended with all 6 LLM canaries
- `tests/test_llm_injection.py` — 33 tests covering metadata, routing, attempt count, body shapes, JSON validity, timeout ≥ 10s, endpoint coverage, format coverage, canary indicators, executor integration

### Jenkins CI webhook integration — closes spec §4.6.2 (last remaining CI provider)
- `convex/jenkinsWebhooks.ts` — Notification Plugin JSON shape; FINALIZED + SUCCESS/FAILURE → scan; QUEUED/STARTED/COMPLETED ignored; ABORTED/UNSTABLE ignored; `parseRepoUrlFromJenkins`, `normaliseJenkinsBranch`; `recordJenkinsEvent` internalMutation with `jenkins-build-<repo>-<sha>-<buildNumber>` dedupeKey
- Auth: `X-Jenkins-Token` shared secret (approach B — Buildkite-style), constant-time XOR-accumulator compare, `JENKINS_WEBHOOK_TOKEN` env var
- `POST /webhooks/jenkins` HTTP route; 29 tests; registered in `_generated/api.d.ts`

### HuggingFace Model Provenance Enrichment — closes spec §3.11.2 HF enrichment TODO
- `convex/lib/huggingFaceEnrichment.ts` — pure parser: `isHuggingFaceComponent` (ecosystem + org/model pattern, rejects @-scoped/Go/3-segment names), `extractHFModelId`, `parseHFApiResponse` (license cardData→tag fallback, README.md model card detection, training dataset dedup, gating, commitSha, pipelineTag); 35 tests
- `convex/modelProvenanceIntel.ts` — `enrichModelProvenanceFromHF` internalAction (HF_FETCH_BATCH=5 parallel fetch, per-model fault isolation); `persistEnrichedModelProvenance` internalMutation; `getLatestSnapshotForRepo` + `getSnapshotComponents` internalQuery helpers; explicit `as Doc<>` casts break circular-inference issue
- Two-phase wiring in `sbom.ts`: baseline (`refreshModelProvenance`) fires immediately; HF-enriched scan fires concurrently and supersedes baseline; `HUGGINGFACE_API_TOKEN` optional env var

### Splunk/Elastic SIEM push — closes spec §4.6.5 SIEM export TODO
- `convex/lib/siemExport.ts` — `buildSplunkHecBody` (newline-delimited HEC batch), `buildElasticBulkBody` (NDJSON with deterministic `_id`, trailing newline), `isValidSiemUrl`; 29 tests
- `convex/siemIntel.ts` — `pushToSiem` internalAction (Splunk HEC + Elastic _bulk independently; Elastic partial-error detection via `json.errors`); `recordSiemPush` internalMutation (30-row retention); `triggerSiemPushForRepository` public mutation; `getLatestSiemPush` + `getSiemPushHistory` queries
- `schema.ts` — `siemPushLogs` table (union validators for status fields, two indexes)
- Fire-and-forget from `blueAgentIntel.generateAndStoreDetectionRules`; `POST /api/siem/push` HTTP endpoint; `RepositorySiemPanel` dashboard component; registered in `_generated/api.d.ts`
- Config: `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`, `SPLUNK_HEC_INDEX`, `ELASTIC_URL`, `ELASTIC_API_KEY`, `ELASTIC_INDEX`

## What Was Built This Session

**Exploit-First Sandbox Validation — Phase 1** (real HTTP exploit execution replacing local-first MVP)

### Python `services/sandbox-manager/` (new service — replaces Go placeholder)
- `pyproject.toml` — FastAPI + httpx + pydantic-settings + uv toolchain
- `src/sentinel_sandbox/models.py` — `ValidationRequest`, `ValidationResult`, `ExploitAttempt`, `SandboxMode`, `ExploitOutcome`
- `src/sentinel_sandbox/exploits/base.py` — `ExploitModule` ABC
- `src/sentinel_sandbox/exploits/http_probe.py` — 15 sensitive-path probes (/.env, actuator, .git, etc.)
- `src/sentinel_sandbox/exploits/injection.py` — SQLi (9 payloads × 3 params), XSS (4 payloads), CMDi (6 payloads)
- `src/sentinel_sandbox/exploits/auth_bypass.py` — JWT alg:none, default creds, IP spoof headers
- `src/sentinel_sandbox/exploits/cve_patterns.py` — Log4Shell (2 patterns), Spring4Shell, ProxyLogon, F5 BIG-IP, path traversal, PHP-FPM RCE
- `src/sentinel_sandbox/executor.py` — orchestrates modules → execute → **classify_outcome() [USER TODO]** → PoC
- `src/sentinel_sandbox/poc.py` — curl one-liner + runnable Python script
- `src/sentinel_sandbox/app.py` — FastAPI: `/health`, `/validate`, `/poc`
- `conftest.py` — sys.path fix for uv test runner
- **45 tests passing** (test_exploits.py, test_executor.py, test_poc.py)

### Convex additions
- `schema.ts` — `sandboxEnvironments` table with full evidence fields + 3 indexes
- `sandboxValidation.ts` (new) — `triggerSandboxValidation` internalAction, `persistSandboxResult`, `markSandboxFailed`, `getSandboxSummaryForRepository`, `getSandboxSummaryBySlug`, `getLatestSandboxEnvironment`
- `events.ts` — fire-and-forget `triggerSandboxValidation` wired after exploitValidationRuns creation (overrides local-first result when sandbox completes)
- `http.ts` — `GET /api/sandbox/environment`, `GET /api/sandbox/summary` (both API-key-guarded)
- `_generated/api.d.ts` — `sandboxValidation` module registered manually (next `convex dev` will regenerate)

### Dashboard
- `src/routes/index.tsx` — `RepositorySandboxPanel` component (exploit counts, PoC badge, winning payload label, evidence summary)
- `RepositorySandboxPanel` wired into per-repository cards after `RepositoryPosturePanel`

### Verified status
- `bun run test`: **442/442 passing (22 files)**
- `bunx tsc --noEmit`: **clean**
- `bun run check` (biome): **clean**
- `bun run build`: **clean (82 kB index bundle)**
- Python `python -m compileall src/`: **clean** (sandbox-manager)
- Python **45/45 tests**: **clean** (sandbox-manager)

## What Was Built In Second Session

### `classify_outcome()` — sandbox executor complete
- Confidence-tiered model in `executor.py` with 16 tests: definitive indicators → EXPLOITED, 2+ successes → EXPLOITED, single weak match → LIKELY_EXPLOITABLE, SQL/traceback error → LIKELY_EXPLOITABLE, dry-run → NOT_EXPLOITABLE(0.0)
- Python test suite: **63/63 passing**

### Tier 1 Breach Intel — all 5 missing feeds added
- `convex/lib/breachFeeds.ts` — 5 new normalizers: `normalizeNvdCve`, `normalizeNpmAdvisory`, `normalizePypiSafetyEntry`, `normalizeRustSecAdvisory`, `normalizeGoVulnEntry`
- `convex/breachIngest.ts` — 5 new sync actions: `syncNvdAdvisories`, `syncNpmAdvisories`, `syncPypiSafetyAdvisories`, `syncRustSecAdvisories`, `syncGoVulnAdvisories`
- Schema `breachDisclosures.sourceType` updated to 8 types; `NormalizedFeedSourceType` extended
- `disclosureToIngestArgs()` shared helper for flat → ingestBreachDisclosure mapping
- NVD supports `NVD_API_KEY` env for higher rate limits

### Slack Integration — `convex/slack.ts`
- Block Kit messages for 3 alert kinds: `finding_validated`, `gate_blocked`, `honeypot_triggered`
- Severity filter: `SLACK_MIN_SEVERITY` env var (default: high)
- `sendWeeklyPostureDigest` internalAction: per-repo open findings summary
- Weekly digest cron added to `crons.ts` (Monday 09:00 UTC)
- Fire-and-forget wired: events.ts (finding.validated) + gateEnforcement.ts (gate.blocked)
- New env vars: `SLACK_WEBHOOK_URL`, `SLACK_MIN_SEVERITY`, `SLACK_ALERT_CHANNEL` (label only)

### GitLab Webhook Integration — `convex/gitlabWebhooks.ts`
- `POST /webhooks/gitlab` HTTP route in http.ts
- Shared-secret verification via `GITLAB_WEBHOOK_TOKEN` env var (fail-open in local dev)
- Push Hook → `ingestGitLabPush` action → `recordGitLabPushEvent` mutation (idempotent)
- Merge Request Hook → processes open/merge actions only
- Fire-and-forget prompt injection scan on commit messages (provider=gitlab)
- `by_provider_and_full_name` index used for GitLab repo lookup

### Verified status
- `bun run test`: **453/453 passing (22 files)**
- `bunx tsc --noEmit`: **clean**
- `bun run check` (biome): **clean**
- `bun run build`: **clean (82 kB index bundle)**
- Python `uv run pytest`: **63/63 passing**

## ⚠️ USER CONTRIBUTION NEEDED (no longer blocking)

`services/sandbox-manager/src/sentinel_sandbox/executor.py` — implement `classify_outcome()`:

```python
def classify_outcome(
    attempts: list[ExploitAttempt],
    req: ValidationRequest,
) -> tuple[ExploitOutcome, float]:
```

The function is at line ~145 in executor.py. The docstring explains the design trade-offs.
The test `test_executor.py::test_dry_run_no_live_requests` is excluded until it's implemented.

## Current Blockers

- `classify_outcome()` not implemented → sandbox always raises NotImplementedError (fire-and-forget, so won't break existing flow)
- Go is not installed — Go service folders are architectural placeholders only
- GitHub webhook secret must be set: `npx convex env set GITHUB_WEBHOOK_SECRET <value>`
- GitHub token must be set: `npx convex env set GITHUB_TOKEN <value>`
- API key not activated: `npx convex env set SENTINEL_API_KEY <value>`
- Sandbox manager URL not set: `npx convex env set SANDBOX_MANAGER_URL http://localhost:8001`

## What Was Built In Ninth Session

### Microsoft Teams Integration — `convex/teams.ts` + `convex/lib/teamsCards.ts`
- `convex/lib/teamsCards.ts` — pure Adaptive Card builder library: `buildTeamsPayload()`, `severityToColor()`, `severityLabel()`, `meetsMinSeverity()` helpers; Adaptive Card envelope schema
- 3 alert card types: finding_validated (with severity color + fact set + blast radius container + PR action), gate_blocked (attention color), honeypot_triggered (breach indicator)
- `sendTeamsAlert` internalAction + `recordTeamsDelivery` audit mutation + `sendWeeklyTeamsDigest` internalAction
- `listRepoSummariesBySlug` internalQuery (mirrors Slack digest data source)
- Severity filter: `TEAMS_MIN_SEVERITY` env var (default: high); honeypots bypass filter
- Fire-and-forget wired into events.ts (finding_validated) + gateEnforcement.ts (gate_blocked) + honeypotIntel.ts (honeypot_triggered)
- Weekly Teams digest cron: every Monday 09:15 UTC (15 min after Slack to avoid simultaneous calls)
- Env vars: `TEAMS_WEBHOOK_URL`, `TEAMS_MIN_SEVERITY`
- 29 pure unit tests covering card structure, severity mapping, min-severity filter, action presence

### Opsgenie Integration — `convex/opsgenie.ts` + `convex/lib/opsgeniePayload.ts`
- `convex/lib/opsgeniePayload.ts` — pure Opsgenie Alerts API v2 payload builder: `buildCreateAlertBody()`, `buildCloseAlertBody()`, `buildOpsgenieAlias()`, `sentinelSeverityToOpsgenieP()` (critical→P1, high→P2, medium→P3, low→P4)
- 3 alert kinds: critical_finding, gate_blocked, honeypot_triggered (always P1 regardless of severity field)
- Deterministic alias for idempotent dedup; responders array wired from `OPSGENIE_TEAM_ID` env
- `sendOpsgenieAlert` internalAction + `pageOnConfirmedExploit` + `pageOnHoneypotTrigger` + `resolveOpsgenieAlert` (closes by alias after post-fix validation)
- Severity threshold: `OPSGENIE_SEVERITY_THRESHOLD` env var (default: critical); honeypots bypass
- Fire-and-forget wired into events.ts (finding_validated) + gateEnforcement.ts (gate_blocked) + honeypotIntel.ts (honeypot_triggered)
- Env vars: `OPSGENIE_API_KEY`, `OPSGENIE_TEAM_ID`, `OPSGENIE_SEVERITY_THRESHOLD`
- 24 pure unit tests covering priority mapping, alias generation, body builder, close body

### AI Model Provenance Tracking — spec §3.11.2 Layer 6 (`convex/lib/modelProvenance.ts`)
- `convex/lib/modelProvenance.ts` — pure library with 6 provenance signal kinds:
  - `unknown_source` (-25) — model not attributable to known registry (HF, OpenAI, Anthropic, Google, Mistral, etc.)
  - `restricted_license` (-20) — license prohibits commercial use/redistribution (CC-BY-NC, GPL, proprietary)
  - `no_license` (-15) — license field absent
  - `unverified_hash` (-15) — no weights hash to verify against
  - `unpinned_version` (-10) — version is "latest", "main", float-ref, or wildcard
  - `training_data_risk` (-20) — known-problematic dataset referenced (LAION, The Pile, Books1/2)
  - `pre_release_model` (-8) — alpha/beta/rc version suffix
- `assessModelProvenance()` — per-component assessment; `scanModelProvenance()` — repository-level aggregate
- `scoreProvenanceSignals()` — **user contribution function** for custom penalty weighting strategy
- 4-tier risk levels: verified (≥80) / acceptable (≥60) / unverified (≥40) / risky (<40)
- `modelProvenanceScans` schema table (bounded 20 per repo; by_repository_and_scanned_at index)
- `convex/modelProvenanceIntel.ts` — `refreshModelProvenance` internalMutation + `refreshModelProvenanceForRepository` public mutation + `getLatestModelProvenance` + `getModelProvenanceHistory` public queries
- Fire-and-forget wired into `sbom.ingestRepositoryInventory` (after model supply chain scan)
- `RepositoryModelProvenancePanel` dashboard component (risk level pill, aggregate score, per-model source+license pills, top signal kind labels)
- Env vars: none (hash verification requires HF API integration — future work)
- 30 pure unit tests covering all signal kinds, score invariants, repo-level aggregation

### Verified Status (Session 9)
- `bun run test`: **723/723 passing (32 files)** — +83 from 640
- `bunx tsc --noEmit`: **clean**
- `bun run check` (biome): **clean**
- `bun run build`: **clean (92 kB index bundle)**
- `convex/_generated/api.d.ts` — manually updated with `teams`, `opsgenie`, `modelProvenanceIntel`, `lib/teamsCards`, `lib/opsgeniePayload`, `lib/modelProvenance`

## What Was Built In Tenth Session

### Buildkite Webhook Integration — `convex/buildkiteWebhooks.ts` (spec §4.6.2)
- Closes the CI/CD integration story: GitHub ✅ GitLab ✅ Bitbucket ✅ Azure DevOps ✅ CircleCI ✅ **Buildkite ✅**
- Shared-secret token verification via `X-Buildkite-Token` header (constant-time XOR, no HMAC)
- `parseRepoUrlFromBuildkite()` — exported pure function; handles SSH (github, bitbucket) + HTTPS (with/without .git)
- Events: `build.finished` state=passed/failed → scan; `build.scheduled`/`build.running` → ignore; `ping` → heartbeat; `build.finished` state=blocked/canceled → ignore
- `BUILDKITE_WEBHOOK_TOKEN` env var; fail-open in local dev
- `POST /webhooks/buildkite` HTTP route added to `http.ts`
- 32 tests covering URL parsing (10 cases), token verification, event routing, dedup key format, summary string format

### Prometheus + Datadog Observability — spec §4.6.5
- **`convex/lib/prometheusMetrics.ts`** — pure library: `escapeLabelValue`, `formatLabels`, `renderMetricLine`, `renderMetricFamily`, `buildMetricsPage`, `sentinelMetricsToSamples`; exports 7 sentinel metrics families (attack_surface_score, open_findings×4 severities, gate_blocked_total, trust_score_average, red_agent_win_rate, provenance_score, compliance_evidence_score×N frameworks); 31 tests
- **`convex/lib/datadogPayload.ts`** — pure library: `buildTags`, `buildDatadogSeries`, `buildDatadogPayload`; Datadog Metrics API v2 format, type=3 gauge, epoch-second timestamps, severity/framework extra tags; 17 tests
- **`convex/observabilityIntel.ts`** — Convex query module: `getActiveTenantSlugs` internalQuery; `loadRepositoryMetrics` internalQuery; `getMetricsSnapshot` public query (loads attack surface, findings, gate decisions, trust score, red agent win rate, provenance, compliance evidence for all repos of a tenant)
- **`convex/datadog.ts`** — `"use node"` internalAction module: `pushMetricsToDatadog` (single tenant/repo), `pushAllTenantMetrics` (all active tenants, for cron)
- **`GET /metrics`** — Prometheus scrape endpoint in `http.ts`; returns `text/plain; version=0.0.4`; optional `PROMETHEUS_SCRAPE_TOKEN` guard; `PROMETHEUS_DEFAULT_TENANT` env var; `?tenantSlug=` override
- **`GET /api/observability/metrics`** — JSON version for API consumers (API-key-guarded)
- Datadog push cron: every 15 minutes via `crons.interval('push datadog metrics', { minutes: 15 }, internal.datadog.pushAllTenantMetrics, {})`
- Env vars: `DD_API_KEY`, `DD_SITE` (default: datadoghq.com), `DD_ENV`, `PROMETHEUS_SCRAPE_TOKEN`, `PROMETHEUS_DEFAULT_TENANT`

### GitHub Issues Ticketing — `convex/githubIssues.ts` + `convex/lib/githubIssuePayload.ts` (spec §4.6.4)
- Completes the 4-system ticketing surface: Jira ✅ Linear ✅ **GitHub Issues ✅** Shortcut ✅
- `convex/lib/githubIssuePayload.ts` — pure library: `buildGithubIssueTitle`, `buildGithubIssueLabels`, `buildGithubIssueBody`, `buildGithubIssueCreateBody`, `buildGithubIssueCloseBody`; 23 tests
- `convex/githubIssues.ts` — `createGithubIssue` internalAction (GitHub REST API v3, X-GitHub-Api-Version header, dedup via reasoningLogUrl prefix "ghissue:"), `closeGithubIssue`, `getGithubIssuesForRepository` public query, `loadGithubFinding` + `patchFindingWithGithubIssue` internal helpers
- Reuses `GITHUB_TOKEN` env var (same as PR generation); `GITHUB_ISSUES_REPO` override
- Finding reference stored as `reasoningLogUrl = "ghissue:{number}:{html_url}"`

### Shortcut Ticketing — `convex/shortcut.ts` (spec §4.6.4)
- Shortcut REST API v3 at `api.app.shortcut.com/api/v3`; `Shortcut-Token` auth header
- `createShortcutStory` internalAction (story_type=bug, severity→estimate 1–8, `completeShortcutStory` discovers "Done" state via `GET /workflows`)
- `getShortcutStoriesForRepository` public query
- Finding reference: `reasoningLogUrl = "shortcut:{story_public_id}:{app_url}"`
- Env vars: `SHORTCUT_API_TOKEN`, `SHORTCUT_WORKFLOW_STATE_ID`, `SHORTCUT_PROJECT_ID`, `SHORTCUT_TEAM_ID`

### Verified Status (Session 10)
- `bun run test`: **826/826 passing (36 files)** — +103 from 723
- `bunx tsc --noEmit`: **clean**
- `bun run check` (biome — src/ only): **clean**
- `bun run build`: **clean (92 kB index bundle)**
- `convex/_generated/api.d.ts` — manually updated with `buildkiteWebhooks`, `observabilityIntel`, `datadog`, `githubIssues`, `shortcut`, `lib/prometheusMetrics`, `lib/datadogPayload`, `lib/githubIssuePayload`

## ⚠️ USER CONTRIBUTION AVAILABLE

`convex/lib/modelProvenance.ts` — implement `scoreProvenanceSignals()`:

```typescript
export function scoreProvenanceSignals(
  signals: ProvenanceSignal[],
  _baseScore: number,
): number {
  // Your implementation here
}
```

The placeholder at line ~200 subtracts penalties linearly (clamped 0–100).
Consider: hard floor for `training_data_risk` regardless of other signals;
multiplicative compounding for multiple signals; ecosystem-specific base scores.
Tested by: `modelProvenance.test.ts` lines 185–200.

## What Was Built In Eighth Session

### CircleCI Webhook Integration — `convex/circleciWebhooks.ts`
- Completes WS-05: GitHub ✅ GitLab ✅ Bitbucket ✅ Azure DevOps ✅ **CircleCI ✅**
- HMAC-SHA256 via `circleci-signature: v1=<hex>` header
- `parseCircleCiSlug()` extracts `org/repo` from `gh/org/repo`, `bb/...`, `gl/...` slugs
- `workflow-completed` → repository scan workflow; `job-completed` → acknowledged only; `ping` → heartbeat
- `CIRCLECI_WEBHOOK_SECRET` env var; fail-open in local dev
- `POST /webhooks/circleci` HTTP route in `http.ts`
- 20 tests

### AI/ML Model Supply Chain Monitoring — spec §3.5
- `convex/lib/modelSupplyChain.ts` — pure lib: 5 risk signal kinds across 150+ ML package catalogue
  - `pickle_serialization_risk` — torch/tensorflow/dill load .pkl by default (RCE vector)
  - `remote_weight_download` — transformers/huggingface_hub download model weights at runtime
  - `unpinned_ml_framework` — ML package with `*`, `>=`, `^`, `~` version constraint
  - `outdated_ml_framework` — version in known CVE range (torch CVE-2022-45907, tf CVE-2023-25668, transformers CVE-2024-3568)
  - `model_typosquat_risk` — name ≤2 Levenshtein edits from well-known ML package
- `modelSupplyChainScans` schema table (by_repository_and_scanned_at)
- `convex/modelSupplyChainIntel.ts` — `refreshModelSupplyChain` internalMutation, `refreshModelSupplyChainForRepository` mutation, `getLatestModelScan` + `getModelScanHistory` public queries
- Fire-and-forget wired into `sbom.ingestRepositoryInventory` (after SBOM component insertion)
- `RepositoryModelSupplyChainPanel` dashboard component (ML frameworks, pickle risk pill, CVE count, flagged packages)
- 30 tests

### SOC 2 Automated Evidence Collection — spec §10.1
- `convex/lib/complianceEvidence.ts` — pure lib: per-framework control catalogues for SOC 2, GDPR, HIPAA, PCI-DSS, NIS2
  - 5 SOC 2 controls (CC6.1, CC6.6, CC7.1, CC7.2, CC8.1) mapped to vuln-class prefixes
  - 4 GDPR controls (Art.32.1a, Art.32.1b, Art.32.1d, Art.33)
  - 4 HIPAA controls (§164.312a/b/c/e)
  - 4 PCI-DSS controls (Req6.3, Req6.4, Req7.1, Req10.2)
  - 4 NIS2 controls (Art.21 2a/2b/2e/2h)
  - Evidence types: finding_log / remediation_timeline / gate_enforcement / risk_acceptance / pr_audit_trail
  - Evidence score 0–100 (compliant+remediated controls / total controls)
- `complianceEvidenceSnapshots` schema table (bounded 20 items/framework; by_repository_and_generated_at)
- `convex/complianceEvidenceIntel.ts` — `refreshComplianceEvidence` internalMutation (all 5 frameworks in one call), `refreshComplianceEvidenceForRepository` mutation, `getLatestComplianceEvidence` + `getAllFrameworkEvidence` + `getFrameworkEvidenceBySlug` public queries
- Fire-and-forget wired into `events.ingestCanonicalDisclosure` (final enrichment step after learning profile)
- `GET /api/compliance/evidence?tenantSlug=<slug>&repositoryFullName=<name>[&framework=soc2]` HTTP endpoint
- `RepositoryComplianceEvidencePanel` dashboard component (per-framework evidence scores, open gap count)
- 31 tests

### Verified status
- `bun run test`: **640/640 passing (29 files)** — +71 from 569
- `bunx tsc --noEmit`: **clean**
- `bun run check` (biome): **clean**
- `bun run build`: **clean (89.62 kB index bundle)**
- `convex/_generated/api.d.ts` — manually updated with `circleciWebhooks`, `modelSupplyChainIntel`, `complianceEvidenceIntel`, `lib/modelSupplyChain`, `lib/complianceEvidence`

## What Was Built In Seventh Session

### Tier 3 Breach Feeds — `convex/tier3BreachFeeds.ts`
- Paste site monitoring: Pastebin RSS + credential pattern detection (npm/GitHub/AWS token regex)
- HaveIBeenPwned: HIBP API v3 domain search → per-breach detail fetch → `normalizeHibpDomainBreach`
- Dark web scaffold: `ingestDarkWebMention` mutation + `normalizeDarkWebMention` (operator/third-party feeds)
- 14 new normalizer tests; schema + events.ts extended with paste_site/credential_dump/dark_web_mention types

### Zero-Day Anomaly Detection — `convex/lib/zeroDayAnomaly.ts`
- Algorithm: compute centroid of rolling 15-push embedding baseline, measure cosine distance of new push
- 4 anomaly levels: normal / watch (>0.20) / suspicious (>0.35) / anomalous (>0.55)
- `scoreAnomalyAdaptive` computes per-repo std deviation and raises thresholds for high-churn repos
- Wired into `semanticFingerprintIntel.analyzeCodeChange` — every push is scored automatically
- 21 tests; `anomalyLevel`/`anomalyScore`/`anomalySummary` added to `codeContextEmbeddings` schema

### GitHub Enterprise Server — `convex/lib/githubClient.ts`
- `resolveGitHubConfig()` reads GHES_BASE_URL/GHES_API_URL → unified API base URL
- `breachIngest.ts` advisory sync updated to use client (GHES-compatible)
- `createGhesAdvisory()` for GHES 3.7+ private vulnerability reporting API

### MSSP White-Label API — `convex/mssp.ts`
- 5 HTTP routes: POST/GET /api/mssp/tenants, GET/DELETE /api/mssp/tenant, GET /api/mssp/dashboard
- `requireMsspApiKey()` guard reads MSSP_API_KEY (fail-closed — 503 if not configured)
- `getCrossTenantDashboard` aggregates risk across all active tenants
- MSSP_BRAND_NAME env var for white-labeling

### LLM Call Chain Detection — `services/agent-core/analyzers/llm_callchain.py`
- Python AST walker for 14 LLM frameworks (OpenAI, Anthropic, LangChain, Vercel AI SDK, LlamaIndex, Google GenAI, Cohere, Mistral, Groq, Replicate, Together)
- JS/TS regex detection for same frameworks
- 4-tier input classification: DIRECT_USER_INPUT (critical), INDIRECT_INPUT (high), UNKNOWN (medium), STATIC (low)
- agent-core v0.3.0: `POST /analyze/llm-callchains` endpoint
- 12 new Python tests → 24 total agent-core tests

### Verified status
- `bun run test`: **569/569 passing (26 files)**
- `bunx tsc --noEmit`: **clean**
- `bun run check` (biome): **clean**
- `bun run build`: **clean**
- Python agent-core: **24/24 passing** (↑ from 12)
- Python sbom-ingest: **22/22 passing**
- Python sandbox-manager: **63/63 passing**

## What Was Built In Sixth Session

### Tier 2 Breach Feeds — `convex/tier2BreachFeeds.ts` + `convex/lib/breachFeeds.ts`
- 4 new normalizers: `normalizeGithubIssueDisclosure`, `normalizeHackerOneReport`, `normalizeOssSecurityPost`, `normalizePacketStormEntry`
- 4 new sync actions: `scanGithubIssuesForPackage`, `syncHackerOneDisclosures`, `syncOssSecurityList`, `syncPacketStormAdvisories`
- All normalize to same `NormalizedDisclosure` → same ingestion pipeline (tier_2 sourceTier)
- Schema + events.ts sourceType extended: github_issues, hackerone, oss_security, packet_storm
- 17 new breachFeeds tests → 534 total Convex tests
- New env vars: HACKERONE_API_IDENTIFIER, HACKERONE_API_KEY (optional)

### Real Attack Surface Analysis (spec §3.7) — `services/agent-core/`
- `analyzers/import_graph.py` — import graph builder:
  - JS/TS: regex-based import/require extraction
  - Python: AST-based import extraction (including `__import__()`)
  - Detects: unused packages, test-only packages, single-use packages, unreachable files
  - `analyze_attack_surface()` returns `AttackSurfaceReport` with `attack_surface_reduction_score()`
- `app.py` upgraded to v0.2.0: `POST /analyze/attack-surface` endpoint
- `attackSurfaceIntel.ts`: `runStaticAttackSurfaceAnalysis` internalAction + `storeStaticAnalysisFindings`
- 12 new Python agent-core tests
- New env var: AGENT_CORE_URL (default: http://localhost:8002)

### Azure DevOps Webhook — `convex/azureDevOpsWebhooks.ts`
- Basic auth verification (ADO uses Authorization header unlike HMAC)
- `git.push` → `recordAdoPushEvent` (idempotent dedupeKey guard)
- `git.pullrequest.merged` → `handlePrMerged` (post-fix validation)
- `POST /webhooks/azure-devops` HTTP route
- SCM coverage now: GitHub ✅ · GitLab ✅ · Bitbucket ✅ · Azure DevOps ✅
- New env var: AZURE_DEVOPS_WEBHOOK_SECRET

### Verified status
- `bun run test`: **534/534 passing (25 files)** — +17 from 517
- `bunx tsc --noEmit`: **clean**
- `bun run check` (biome): **clean**
- `bun run build`: **clean**
- Python agent-core: **12/12 passing** (new)
- Python sbom-ingest: **22/22 passing**
- Python sandbox-manager: **63/63 passing**

## What Was Built In Fifth Session

### Blue Agent — `convex/lib/blueAgent.ts` + `convex/blueAgentIntel.ts`
- Pure detection rule generator: 8 vuln class templates × 5 output formats (nginx, ModSecurity, Splunk SPL, Elastic KQL, Sentinel KQL, log regex)
- 22 tests covering all formats, deduplication, rule content structure
- `detectionRuleSnapshots` schema table (bounded storage)
- Fire-and-forget wired into `redBlueIntel.ts` on red_wins
- `GET /api/detection-rules?format=...` HTTP endpoint — nginx/ModSec as downloadable .conf text

### Post-Fix Validation Loop — `convex/postFixValidation.ts`
- `handlePrMerged` internalAction → 60s delay → `runPostFixValidation` (sandbox re-exploit)
- Exploit fails on patched code → `markFindingResolved` + Linear/Jira ticket resolved
- Exploit succeeds → `reopenFinding` + Slack critical regression alert
- GitHub webhook now handles `pull_request` event (action:closed + merged:true)
- Fallback to optimistic resolution when no sandbox URL configured

### Linear Integration — `convex/linear.ts`
- Linear GraphQL API: `createLinearIssue` (Markdown description builder), `completeLinearIssue` (finds Done state via workflowStates), `getLinearTicketsForRepository`
- Env vars: LINEAR_API_KEY, LINEAR_TEAM_ID, LINEAR_PROJECT_ID, LINEAR_ASSIGNEE_ID

### Bitbucket Cloud Webhook — `convex/bitbucketWebhooks.ts`
- HMAC-SHA256 signature verification (X-Hub-Signature header)
- `repo:push` → `recordBitbucketPushEvent` (idempotent)
- `pullrequest:fulfilled` → `handlePrMerged` (post-fix validation)
- `POST /webhooks/bitbucket` HTTP route

### Verified status
- `bun run test`: **517/517 passing (25 files)** — +22 from 495
- `bunx tsc --noEmit`: **clean**
- `bun run check` (biome): **clean**
- `bun run build`: **clean**

## What Was Built In Fourth Session

### GitHub Actions Native CI Action — `apps/github-action/`
- Full Node.js GitHub Action: `action.yml` metadata, `sentinel-api.ts` client, `check-run.ts` PR report builder, `index.ts` gate logic
- Inputs: `sentinel-api-key`, `tenant-slug`, `block-on-severity` (critical/high/medium/none), `post-check-run`, `fail-on-error`
- Outputs: `gate-decision` (pass/block/skip), `finding-count`, `critical-count`, `high-count`, `check-run-url`
- Posts GitHub Check Run with severity table, blast radius, fix PR links, posture score
- `examples/security-gate.yml` — ready-to-use workflow with `checks: write` permission
- 14 tests passing

### Supply Chain Social Monitor — `convex/supplyChainMonitor.ts`
- Real GitHub API calls for dependency repository health signals:
  - Archived/abandoned detection (no pushes > 2 years)
  - New-account high-contributions (> 20% recent commits from accounts < 1 year old)
  - Build script modified by new contributor (CRITICAL signal)
  - Release by non-established contributor (recent release from someone not in top-10)
  - Low contributor diversity for popular packages
  - High issue-to-stars ratio
- `supplyChainAnalyses` schema table; `batchAnalyzeSnapshotSupplyChain` processes 10 deps per call
- `getSupplyChainRiskSummary` + `getPackageSupplyChainAnalysis` public queries
- `triggerSupplyChainAnalysis` dashboard mutation

### Jira Integration — `convex/jira.ts`
- Jira Cloud REST API v3 with proper Atlassian Document Format (heading, paragraph, bulletList nodes)
- `createJiraIssue`: loads finding, builds ADF body (summary, blast radius, files, packages, regulatory, PR link), posts to /rest/api/3/issue, patches finding with `jira:KEY:URL` ref
- `resolveJiraIssue`: auto-transitions to "Done" via available transitions API
- `getJiraTicketsForRepository`: public query for dashboard
- Env vars: JIRA_BASE_URL, JIRA_API_TOKEN, JIRA_PROJECT_KEY, JIRA_ISSUE_TYPE, JIRA_ASSIGNEE_ACCOUNT_ID

### NuGet + Composer SBOM Parsers — completes all 8 spec ecosystems
- NuGet: `_parse_csproj()` (PackageReference inline + child element), `_parse_nuget_lock()` (packages.lock.json with Direct/Transitive)
- Composer: `_parse_composer_lock()` (packages/packages-dev), `_parse_composer_json()` (bare fallback, excludes php/ext-*)
- Lock files take precedence over manifest files
- 6 new tests → 22 total sbom-ingest tests

### Verified status
- `bun run test`: **495/495 passing (24 files)**
- `bunx tsc --noEmit`: **clean**
- `bun run check` (biome): **clean**
- `bun run build`: **clean**
- Python sbom-ingest: **22/22 passing** (↑ from 16)
- Python sandbox-manager: **63/63 passing**
- GitHub Action: **14/14 passing**

## What Was Built In Third Session

### Semantic Fingerprinting — Real Embeddings (spec §3.1)
- `convex/lib/codeEmbedding.ts` — `cosineSimilarity`, `normalize`, `embedText`, `embedBatch` (OpenAI), `searchPatterns`, `buildCodeContext`; 30 tests
- `convex/lib/vulnerabilityPatternLibrary.ts` — 52 curated vulnerability descriptions across OWASP Top 10 + AI/LLM classes (SVF-0001 through SVF-0171)
- `convex/semanticFingerprintIntel.ts` — `initializePatternLibrary` internalAction (batch-embeds all patterns), `analyzeCodeChange` internalAction (embed code context → cosine search → store top matches), `getPatternLibraryStatus` / `getLatestCodeAnalysis` / `getCodeAnalysisHistory` public queries
- `vulnerabilityPatternEmbeddings` + `codeContextEmbeddings` schema tables
- Fire-and-forget wired into `events.ts` push workflow (runs after path-aware fallback)
- `RepositorySemanticFingerprintPanel` dashboard component
- Cost: ~$0.00002 per push event; fails open with path-aware fallback when OPENAI_API_KEY absent

### SPDX 2.3 Export (spec §3.11.4)
- `convex/lib/spdx.ts` — pure SPDX 2.3 JSON builder: SPDXID namespacing, PURL refs, DEPENDS_ON/DEPENDENCY_OF relationships, license normalization, trust score annotations; 20 tests
- `convex/sbom.ts` — `exportSnapshotAsSpdx` query
- `GET /api/sbom/export?format=spdx` endpoint (alongside `?format=cyclonedx`)

### Maven/Gradle/Ruby SBOM Parsers (spec §3.11 Layer 1)
- `_parse_pom_xml()` — Maven pom.xml with namespace support, scope→layer mapping
- `_parse_gradle()` — Groovy + Kotlin DSL regex patterns
- `_parse_gemfile_lock()` / `_parse_gemfile()` — full specs/DEPENDENCIES parsing
- All wired into `analyze_repository()`; 11 new Python tests → 16 total sbom-ingest tests

### PagerDuty Integration (spec §4.6.3)
- `convex/pagerduty.ts` — Events API v2: `sendPagerDutyAlert` / `pageOnConfirmedExploit` / `pageOnHoneypotTrigger` / `resolveIncident`
- `PAGERDUTY_SEVERITY_THRESHOLD` filter (default: critical)
- dedup_key for idempotent alerting
- Wired into `honeypotIntel.ts` recordHoneypotTrigger

### Verified status
- `bun run test`: **495/495 passing (24 files)** — +42 from 453
- `bunx tsc --noEmit`: **clean**
- `bun run check` (biome): **clean**
- `bun run build`: **clean (85 kB index bundle)**
- Python sbom-ingest: **16/16 passing** — +11 from 5 original tests
- Python sandbox-manager: **63/63 passing**

## Immediate Next Steps

1. Start sandbox-manager: `cd services/sandbox-manager && uv run uvicorn sentinel_sandbox.app:app --port 8001`
2. Set `SANDBOX_MANAGER_URL` in Convex: `npx convex env set SANDBOX_MANAGER_URL http://localhost:8001`
3. Set `GITHUB_WEBHOOK_SECRET`: `npx convex env set GITHUB_WEBHOOK_SECRET <secret>`
4. Set `GITLAB_WEBHOOK_TOKEN`: `npx convex env set GITLAB_WEBHOOK_TOKEN <token>`
5. Set `SLACK_WEBHOOK_URL`: `npx convex env set SLACK_WEBHOOK_URL https://hooks.slack.com/services/...`
6. Set `GITHUB_TOKEN` and run first live advisory sync
7. Set `SENTINEL_API_KEY` to activate HTTP auth guard
8. Set `NVD_API_KEY` (optional): `npx convex env set NVD_API_KEY <key>` for higher NVD rate limits
9. Set `OPENAI_API_KEY`: `npx convex env set OPENAI_API_KEY sk-...` then run `initializePatternLibrary` once
10. Set `PAGERDUTY_INTEGRATION_KEY`: `npx convex env set PAGERDUTY_INTEGRATION_KEY <routing-key>`
11. Set Jira env vars (optional): JIRA_BASE_URL, JIRA_API_TOKEN, JIRA_PROJECT_KEY
12. Run `npx convex dev` to regenerate `_generated/api.d.ts`

## Roadmap Position

- Done:
  - stack decisions
  - repo scaffold
  - initial service boundaries
  - first control-plane schema
  - first dashboard shell
- In progress:
  - repository bootstrap
  - core platform services
  - data plane foundation
  - SBOM ingestion pipeline
  - breach intel MVP
- Recently completed:
  - local Convex initialization and backend code generation
  - GitHub webhook HTTP ingest path in code
  - scheduled and bulk advisory sync path in code
  - Breach Intel Aggregator MVP with sync-run persistence and dashboard feed health
  - Semantic Fingerprinting MVP with path-aware candidate findings and dashboard visibility
  - Exploit Validation MVP with validation-run persistence and workflow advancement
  - CI/CD Gate Enforcement MVP with policy engine, per-finding gate decisions, override support, and dashboard enforcement panel
  - PR Generation MVP with proposal generation, GitHub API integration (branch + draft PR), finding lifecycle advancement, and dashboard prGeneration panel
- Recently completed:
  - WS-13 ingestion wiring and dashboard panel (injection scans on push + advisory intake; `RepositoryIntelligencePanel`)
  - WS-14 Phase 2: Memory Controller + Red/Blue simulation loop MVP
  - Trust Score Computation Pipeline: `componentTrustScore.ts` pure lib (30 tests), `trustScoreIntel.ts` Convex entrypoints, fire-and-forget wiring in sbom.ts + events.ts, `trust_score.compromised` 11th webhook event type, 11/11 webhook coverage
  - Dashboard UX pass: `RepositoryTrustScorePanel` + `TrustScoreTierBar` fully implemented; `convex/_generated/api.d.ts` updated; tsc + biome + 442 tests all green
  - WS-96: Security Configuration Drift Posture Score — weighted composite of all 36 drift detectors into a single 0–100 score per repository; `driftPostureResults` schema; `RepositoryDriftPosturePanel`; 0 TS errors
  - WS-97: Tenant Security Executive Report — pure computed view synthesising WS-49 health (40%), WS-96 drift (35%), WS-44 supply chain (15%), WS-46 compliance (10%) across all tenant repositories; `executiveReportIntel.ts` (2 queries, no new schema table); `GET /api/tenant/executive-report`; `TenantExecutiveReportPanel` (first panel in tenant section); 54 pure-lib tests; 8260/8260 total tests pass, 0 TS errors
  - Fixed `vi.stubGlobal` not-a-function failures in `webhookDispatcher.test.ts` (bun test runner incompatibility; replaced with beforeEach/afterEach pattern; 32/32 tests pass)
  - WS-98: Zero-Day Anomaly Detection (spec §3.1.3) — 8-signal heuristic static analysis engine for novel attack patterns when no CVE/fingerprint match; `zeroDayDetector.ts` pure lib (74 tests); `zeroDayDetections` schema table; `zeroDayDetectionIntel.ts` (5 entrypoints); fire-and-forget in events.ts; `GET /api/repository/zero-day-detections?tenantSlug=&repositoryFullName=` HTTP route; `RepositoryZeroDayDetectionPanel` dashboard component
  - WS-99: Security Program Maturity Model — CMMI-style 5-level assessment (Initial→Optimising) across 6 dimensions reading 16 source tables; `securityMaturityModel.ts` pure lib (40 tests); `maturityAssessments` schema table; `maturityAssessmentIntel.ts` (6 entrypoints, regulatory drift vocabulary mapping); fire-and-forget in events.ts at runAfter(13_000); `GET /api/repository/maturity-assessment?tenantSlug=&repositoryFullName=` HTTP route; `RepositoryMaturityPanel` dashboard component; 8334/8334 total tests, 0 TS errors, biome clean
  - WS-100: Business Impact Assessment (spec §3.5.4) — five-dimension repo-level business risk aggregation (data exposure, regulatory, revenue, reputation, remediation cost); financial estimates (records at risk, fine range, remediation cost); `businessImpact.ts` pure lib (44 tests); `businessImpactSnapshots` schema table; `businessImpactIntel.ts` (6 entrypoints, reads 5 tables in parallel); fire-and-forget in events.ts at runAfter(12_000); `GET /api/repository/business-impact`; `RepositoryBusinessImpactPanel`; 8378/8378 tests, 0 TS errors, biome clean

## Update Rule

Every run must update these files before ending if anything meaningful changed:

1. `CURRENT_CONTEXT.md` for the latest working state and blockers
2. `TODO.md` for the near-term active queue
3. `PROJECT_TRACKER.md` when a workstream or milestone status changes
4. `IMPLEMENTATION_SPLIT.md` only when scope or build order changes
