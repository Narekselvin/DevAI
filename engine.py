import re
from datetime import datetime

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from notifier import TelegramNotifier
from knowledge_db import get_connection
from template_registry import resolve_enterprise_template


def _macro_thresholds(vendor_template_key):
    return resolve_enterprise_template(vendor_template_key).get('macros') or {}


def load_remediation_documents(connection, target_language):
    normalized_language = target_language if target_language in ('en', 'ru', 'hy') else 'en'
    cursor = connection.cursor()
    cursor.execute(
        'SELECT remediation_id, title_en, title_ru, title_hy, mapped_symptoms, '
        'steps_en, steps_ru, steps_hy, nlp_baseline_en FROM remediations ORDER BY remediation_id'
    )
    rows = cursor.fetchall()
    combined_documents = []
    metadata_rows = []
    for (
        remediation_id,
        title_en,
        title_ru,
        title_hy,
        mapped_symptoms_text,
        steps_en,
        steps_ru,
        steps_hy,
        nlp_baseline_en,
    ) in rows:
        combined_documents.append(nlp_baseline_en or '')
        if normalized_language == 'ru':
            localized_title = title_ru
            localized_steps = steps_ru
        elif normalized_language == 'hy':
            localized_title = title_hy
            localized_steps = steps_hy
        else:
            localized_title = title_en
            localized_steps = steps_en
        metadata_rows.append(
            {
                'remediation_id': remediation_id,
                'title': localized_title,
                'resolution_steps': localized_steps,
                'mapped_symptoms': mapped_symptoms_text,
            }
        )
    return combined_documents, metadata_rows


def normalize_free_text_for_matching(raw_text):
    if not raw_text:
        return ''
    collapsed_whitespace = re.sub(r'\s+', ' ', raw_text)
    return collapsed_whitespace.strip().lower()


def build_query_text_from_scanner_payload(scanner_payload):
    fragments = []
    for listener_record in scanner_payload.get('listening_sockets', []):
        fragments.append(
            ' '.join(
                [
                    'listener',
                    str(listener_record.get('port')),
                    str(listener_record.get('protocol')),
                    str(listener_record.get('service_guess')),
                    str(listener_record.get('process_name')),
                    str(listener_record.get('service_version_banner')),
                ]
            )
        )
    for permission_record in scanner_payload.get('weak_permission_findings', []):
        fragments.append(' '.join(permission_record.values()))
    outdated_section = scanner_payload.get('python_package_outdated_report', {})
    for package_record in outdated_section.get('packages', []):
        fragments.append(
            'outdated package '
            + str(package_record.get('name'))
            + ' '
            + str(package_record.get('installed_version'))
            + ' '
            + str(package_record.get('latest_version'))
        )
    for drift_record in scanner_payload.get('configuration_drift_hints', []):
        fragments.append(' '.join(str(value) for value in drift_record.values()))
    return normalize_free_text_for_matching(' '.join(fragments))


def build_query_text_from_antivirus_payload(antivirus_payload):
    fragments = []
    for hash_record in antivirus_payload.get('hash_signature_hits', []):
        fragments.append('suspicious hash signature ' + str(hash_record.get('path')))
    for yara_record in antivirus_payload.get('yara_signature_hits', []):
        fragments.append('yara rule ' + str(yara_record.get('rule')) + ' path ' + str(yara_record.get('path')))
    for isolated_path in antivirus_payload.get('isolated_suspicious_paths', []):
        fragments.append('isolated suspicious path ' + str(isolated_path))
    return normalize_free_text_for_matching(' '.join(fragments))


def build_query_text_from_log_payload(log_payload):
    fragments = []
    for failure_record in log_payload.get('critical_failure_events', []):
        fragments.append(str(failure_record.get('line', '')))
    for unauthorized_record in log_payload.get('unauthorized_access_indicators', []):
        fragments.append(str(unauthorized_record.get('line', '')))
    for downtime_record in log_payload.get('downtime_indicators', []):
        fragments.append(str(downtime_record.get('line', '')))
    for crash_record in log_payload.get('service_crash_events', []):
        fragments.append(
            ' '.join(
                [
                    'service crash',
                    str(crash_record.get('timestamp')),
                    str(crash_record.get('event_code')),
                    str(crash_record.get('error_code')),
                    str(crash_record.get('message_excerpt')),
                ]
            )
        )
    return normalize_free_text_for_matching(' '.join(fragments))


def compute_tfidf_similarity_ranking(query_text, combined_documents, metadata_rows, maximum_results):
    if not combined_documents or not query_text:
        return []
    vectorizer = TfidfVectorizer(max_features=8192, ngram_range=(1, 2))
    document_term_matrix = vectorizer.fit_transform(combined_documents)
    query_vector = vectorizer.transform([query_text])
    similarity_scores = cosine_similarity(query_vector, document_term_matrix).flatten()
    ranked_indices = np.argsort(-similarity_scores)
    ranked_results = []
    for index_position in ranked_indices:
        if len(ranked_results) >= maximum_results:
            break
        score_value = float(similarity_scores[index_position])
        if score_value <= 0.0:
            continue
        metadata_entry = metadata_rows[int(index_position)]
        ranked_results.append(
            {
                'similarity_score': score_value,
                'remediation_id': metadata_entry['remediation_id'],
                'title': metadata_entry['title'],
                'resolution_steps': metadata_entry['resolution_steps'],
            }
        )
    return ranked_results


def generate_structured_remediation_plan(connection, primary_query_text, maximum_matches, target_language='en'):
    combined_documents, metadata_rows = load_remediation_documents(connection, target_language)
    return compute_tfidf_similarity_ranking(primary_query_text, combined_documents, metadata_rows, maximum_matches)


def merge_query_streams(scanner_text, log_text, antivirus_text):
    merged_segments = [scanner_text, log_text, antivirus_text]
    merged_segments = [segment for segment in merged_segments if segment]
    return normalize_free_text_for_matching(' '.join(merged_segments))


def build_query_text_from_snmp_metrics(snmp_metrics):
    fragments = []
    for device in snmp_metrics or []:
        fragments.append(
            ' '.join(
                [
                    str(device.get('hostname', '')),
                    str(device.get('ip', '')),
                    str(device.get('device_type', '')),
                    'vendor_profile',
                    str(device.get('vendor_template', '')),
                    'cpu',
                    str(device.get('cpu_utilization', '')),
                    'ram',
                    str(device.get('ram_usage', '')),
                    'disk',
                    str(device.get('disk_usage', '')),
                    'temp',
                    str(device.get('temperature_c', '')),
                    'latency_ms',
                    str(device.get('latency_ms', '')),
                    'http_status_code',
                    str(device.get('http_status_code', '')),
                    'status',
                    str(device.get('status', '')),
                    'warnings',
                    ' '.join(str(w) for w in device.get('warnings', [])),
                ]
            )
        )
    return normalize_free_text_for_matching(' '.join(fragments))


def _localize(language, en_value, ru_value, hy_value):
    if language == 'ru':
        return ru_value
    if language == 'hy':
        return hy_value
    return en_value


def _load_hardware_playbooks_and_manuals(connection, target_language):
    language = target_language if target_language in ('en', 'ru', 'hy') else 'en'
    cursor = connection.cursor()
    cursor.execute(
        'SELECT issue_key, title_en, title_ru, title_hy, remediation_en, remediation_ru, remediation_hy, nlp_baseline_en, remediation_script '
        'FROM hardware_playbooks ORDER BY playbook_id'
    )
    rows = cursor.fetchall()
    documents = []
    metadata = []
    for issue_key, title_en, title_ru, title_hy, rem_en, rem_ru, rem_hy, baseline, script_value in rows:
        documents.append(baseline or '')
        metadata.append(
            {
                'issue_key': issue_key,
                'title': _localize(language, title_en, title_ru, title_hy),
                'remediation': _localize(language, rem_en, rem_ru, rem_hy),
                'remediation_script': script_value or '',
            }
        )
    cursor.execute(
        'SELECT vendor_key, title_en, title_ru, title_hy, body_en, body_ru, body_hy, nlp_baseline_en FROM system_manuals ORDER BY manual_id'
    )
    for vendor_key, title_en, title_ru, title_hy, body_en, body_ru, body_hy, baseline in cursor.fetchall():
        documents.append(baseline or '')
        metadata.append(
            {
                'issue_key': str(vendor_key),
                'title': _localize(language, title_en, title_ru, title_hy),
                'remediation': _localize(language, body_en, body_ru, body_hy),
                'remediation_script': '',
            }
        )
    return documents, metadata


def _vendor_thermal_clause(vendor_template, language):
    vt = str(vendor_template or '')
    bank = {
        'dell_pe_idrac9': (
            ' Dell PowerEdge iDRAC 9 thermal escalation: validate inlet versus exhaust deltas in OpenManage Enterprise, reseat the front bezel to restore directed airflow, confirm redundant fan groups and empty drive bay fillers, inspect PERC NV cache modules for adjacent hotspotting, and export SupportAssist thermal logs before replacing assemblies.',
            ' Dell PowerEdge iDRAC 9: сравните перепады вход/выход в OpenManage Enterprise, установите передний безель, проверьте вентиляторы и заглушки отсеков, NV-кэш PERC на локальные hotspots, экспорт SupportAssist до замены узлов.',
            ' Dell PowerEdge iDRAC 9 ջերմային աճ՝ համեմատեք մուտք/ելք OpenManage Enterprise-ում, վերակցեք առաջնային բեզելը, ստուգեք հովացուցիչների կրկնությունն ու դատարկ սլոթերի փակիչները, PERC NV cache հարևանությամբ hotspot-ները, SupportAssist արտահանում նախքան հանգույցների փոխարինումը։',
        ),
        'dell_pe_idrac7_8': (
            ' Dell PowerEdge iDRAC 7/8 sustained heat: clear dust from memory shrouds and PCIe risers, verify fan speed curves inside iDRAC thermal profile pages, ensure cable arms do not obstruct midplane channels, and correlate SNMP coolingDeviceLocationName readings with physical rack blanking.',
            ' Dell iDRAC 7/8: очистите пыль с кожухов памяти и riser, проверьте кривые вентиляторов в iDRAC, кабельные рукава не должны перекрывать каналы, сопоставьте SNMP coolingDeviceLocationName с blanking в стойке.',
            ' Dell iDRAC 7/8՝ մաքրեք փոշը հիշողության ծածկերից և PCIe riser-ներից, ստուգեք iDRAC-ում հովացման պրոֆիլները, մալուխի կառավարիչները չպետք է արգելեն միջային հոսքը, SNMP coolingDeviceLocationName-ը համեմատեք արկային blanking-ի հետ։',
        ),
        'dell_powervault_md': (
            ' Dell PowerVault modular thermal stress: confirm enclosure blower duty cycles, verify disk pack spacing for lateral exhaust, check EMS SNMP enclosureHealth against dual power path balance, and stage disk group rebuilds only after inlet temperature stabilizes below policy.',
            ' Dell PowerVault: циклы продувки, зазоры между дисками для бокового выхлопа, SNMP enclosureHealth и баланс БП, rebuild только после стабилизации входной температуры.',
            ' Dell PowerVault՝ ստուգեք փչիչների ցիկլերը, սկավառակների միջանկյալ տարածքները, SNMP enclosureHealth-ը և կրկնակի սնուցման հավասարակշռությունը, rebuild-ը միայն մուտքային ջերմաստիճանի կայունացումից հետո։',
        ),
        'dell_force10_ftos': (
            ' Dell Force10 or OS10 thermal alarms: validate fan tray rotation counters, clean fabric module filters, confirm QSFP heat sinks are seated, and compare entPhysicalSensorTable thresholds with data hall containment leakage before RMA optics.',
            ' Dell Force10/OS10: счетчики вентиляторов, фильтры fabric, радиаторы QSFP, entPhysicalSensorTable против утечек холодного коридора перед RMA оптики.',
            ' Dell Force10/OS10՝ հովացուցիչների հաշվիչներ, ֆիլտրեր, QSFP ջերմափոխանակիչների նստվածություն, entPhysicalSensorTable-ի համեմատություն cold aisle-ի հետ։',
        ),
        'cisco_nexus_nxos': (
            ' Cisco Nexus NX-OS thermal remediation: inspect VDC supervisor airflow orientation, validate crossbar module insertion depth, capture Ethanalyzer-adjacent environmental traps, and verify vPC peer keepalive path heat symmetry before altering fan policies.',
            ' Cisco Nexus NX-OS: ориентация воздуха супервизоров VDC, глубина crossbar, environmental traps рядом с Ethanalyzer, симметрия тепла vPC keepalive перед сменой fan policy.',
            ' Cisco Nexus NX-OS՝ VDC սուպերվիզորի օդի ուղղություն, crossbar մոդուլի խորություն, Ethanalyzer-ին կից environmental թակարդներ, vPC keepalive ջերմային համաչափություն։',
        ),
        'cisco_cat_iosxe': (
            ' Cisco Catalyst IOS-XE heat rise: confirm stackwise cabling does not block side intakes, review show environment all versus SNMP ciscoEnvMonTemperatureStatusValue, validate PoE budget thermal coupling, and schedule RMA only after swapping uplink optics with known-good spares.',
            ' Cisco IOS-XE: StackWise не перекрывает боковые входы, show environment all и SNMP ciscoEnvMonTemperatureStatusValue, связка PoE и тепла, RMA оптики после проверки запасными SFP.',
            ' Cisco IOS-XE՝ StackWise մալուխը չարգելափակի կողային մուտքերը, show environment all և SNMP ciscoEnvMonTemperatureStatusValue, PoE բեռի կապը ջերմության հետ։',
        ),
        'cisco_ucs_fi': (
            ' Cisco UCS Fabric Interconnect thermal excursion: verify chassis inlet sensors against FI SNMP thermal tables, check FEX uplink cable bend radius for restricted exhaust, validate fan redundancy mode, and drain blade workloads before reseating fabric extender links.',
            ' Cisco UCS FI: датчики входа шасси и SNMP FI thermal, радиус изгиба FEX, режим резервирования вентиляторов, слейте нагрузку с лезвий перед пересадкой FEX.',
            ' Cisco UCS FI՝ շասսի մուտքային սենսորներն ու FI SNMP ջերմային աղյուսակները, FEX մալուխի կորություն, հովացուցիչների կրկնակի ռեժիմ։',
        ),
        'cisco_asa_firepower': (
            ' Cisco ASA or Firepower thermal remediation: validate module slot blanking, inspect threat services SSP heat sync with SNMP cfwHardwareStatusValue, confirm redundant power load sharing does not asymmetrically heat one side of the chassis, and capture packet-capture adjacent CPU thermal correlation.',
            ' Cisco ASA/Firepower: заглушки слотов, SSP и SNMP cfwHardwareStatusValue, баланс БП без перекоса тепла, корреляция CPU thermal с захватами.',
            ' Cisco ASA/Firepower՝ մոդուլային blanking, SSP և SNMP cfwHardwareStatusValue, կրկնակի սնուցման ջերմային անհամաչափությունից խուսափում։',
        ),
        'hpe_ilo4_gen89': (
            ' HPE ProLiant iLO 4 Gen8/9 heat climb: open iLO Active Health thermal graphs, verify fan redundancy lost events, reseat memory airflow baffles, confirm Insight Management SNMP cpqHeFltTolFanCondition against physical fan LEDs, and replace failed DIMM thermal sensors only after firmware parity checks.',
            ' HPE iLO4 Gen8/9: графики Active Health, события потери резерва вентиляторов, кожухи памяти, SNMP cpqHeFltTolFanCondition и индикаторы, DIMM датчики после проверки FW.',
            ' HPE iLO4 Gen8/9՝ Active Health գրաֆիկներ, հովացուցիչների կրկնության կորուստ, հիշողության օդային ծածկեր, SNMP cpqHeFltTolFanCondition և LED-ներ։',
        ),
        'hpe_ilo5_gen1011': (
            ' HPE ProLiant iLO 5 Gen10/11 thermal response: use iLO 5 REST or SNMP cpqHeThermalCondition alongside Silicon Root of Trust event logs, validate liquid cooling quick disconnect torque if applicable, and stage firmware baseline upgrades only after inlet normalization.',
            ' HPE iLO5 Gen10/11: REST или SNMP cpqHeThermalCondition с журналами Silicon Root of Trust, проверка QDC жидкости, обновление FW после нормализации inlet.',
            ' HPE iLO5 Gen10/11՝ REST կամ SNMP cpqHeThermalCondition, Silicon Root of Trust մատյաններ, հեղուկային QDC մoment, FW թարմացում inlet նորմալացումից հետո։',
        ),
        'hpe_procurve': (
            ' HPE ProCurve or ArubaOS-Switch legacy thermal remediation: clean side vent mesh, verify fan tray FRU part numbers against PoE load class, compare snmp env temperatures with IR spot checks on uplink PHY banks, and stagger PoE device power-up after cooling recovery.',
            ' HPE ProCurve: сетка вентиляции, FRU вентиляторов и класс PoE, SNMP env и ИК-замеры PHY uplink, поэтапный PoE после охлаждения.',
            ' HPE ProCurve՝ կողային վենտիլյացիոն ցանց, fan FRU և PoE դաս, SNMP env և IR ստուգումներ, PoE վերագործարկումը փուլային։',
        ),
        'hpe_arubaos_cx': (
            ' HPE ArubaOS-CX thermal workflow: validate VSX split-brain cooling symmetry, inspect 100G line card sensor deltas via SNMP ENTITY-SENSOR-MIB, confirm VSX keepalive link does not obstruct front-to-rear airflow, and apply fan speed policy changes during maintenance windows only.',
            ' HPE ArubaOS-CX: симметрия охлаждения VSX, SNMP ENTITY-SENSOR-MIB на 100G линейках, keepalive не блокирует front-to-rear, смена fan policy только в окне.',
            ' HPE ArubaOS-CX՝ VSX ջերմային համաչափություն, ENTITY-SENSOR-MIB 100G քարտերում, keepalive-ը չարգելափակի front-to-rear հոսքը։',
        ),
        'juniper_junos_exsrx': (
            ' Juniper Junos EX/SRX thermal recovery: compare RE and FPC environmental SNMP jnxOperatingTemp against thresholds, verify filter tray servicing intervals, confirm chassis altitude mode settings, and offload sampling-heavy features before increasing fan thresholds.',
            ' Juniper Junos: SNMP jnxOperatingTemp RE и FPC, сервис лотков фильтров, режим высоты шасси, снизьте sampling до повышения fan threshold.',
            ' Juniper Junos՝ jnxOperatingTemp RE և FPC, ֆիլտրի սայրերի սպասարկում, բարձրության ռեժիմ, sampling բեռի նվազեցում։',
        ),
        'fortinet_fortios': (
            ' FortiGate FortiOS thermal mitigation: inspect NP7/CP9 ASIC heat spreaders via diag temperature readings, validate dual PSU intake separation, review UTM-heavy policies that raise dataplane die temperature, and schedule controlled ha failover after verifying fan tach SNMP parity.',
            ' FortiGate: diag temperature для ASIC, раздельные входы БП, UTM политики и температура dataplane, SNMP tach вентиляторов перед ha failover.',
            ' FortiGate՝ diag temperature ASIC-ների համար, երկու PSU մուտքերի բաժանում, UTM քաղաքականությունների ջերմային ազդեցություն, ha failover նախքան tach SNMP համաչափություն։',
        ),
        'paloalto_panos': (
            ' Palo Alto PAN-OS thermal containment: correlate panSysHwGenId thermal zones with SNMP panVsysActiveSessions pressure, validate log card and SSD stack clearance, confirm flexible routing offload is not starving adjacent NP blocks of airflow, and capture tech support thermal sections before hardware swap.',
            ' Palo Alto PAN-OS: panSysHwGenId зоны и panVsysActiveSessions, зазор SSD/log карты, offload маршрутизации и обдув NP, tech support thermal до замены.',
            ' Palo Alto PAN-OS՝ panSysHwGenId գոտիներ և panVsysActiveSessions, SSD/log քարտերի մաքուր տարածք, NP բլոկների օդափոխանակություն, tech support thermal։',
        ),
        'mikrotik_routeros': (
            ' MikroTik RouterOS thermal triage: verify board temperature SNMP mtxrHlTemperature against ambient delta, reduce wireless chain power if RFPA heat couples to SoC, confirm PoE out budget does not brown out the main regulator, and upgrade firmware after checking known thermal regressions.',
            ' MikroTik: mtxrHlTemperature и дельта с ambient, снизьте мощность радио если греется RFPA, PoE out и регулятор, FW после проверки регрессий температуры.',
            ' MikroTik՝ mtxrHlTemperature և ambient դելտա, RFPA ջերմությունը SoC-ին կապակցելիս հզորության նվազեցում, PoE out բյուջե։',
        ),
        'ubiquiti_edgemax': (
            ' Ubiquiti EdgeMAX thermal checks: validate passive or active cooling option kit seating, inspect SFP+ cage proximity to CPU heatsink via SNMP hrDeviceTemperature if exposed, reduce IPSec offload bursts during heat waves, and confirm rack side baffles align with front-to-rear pressure map.',
            ' Ubiquiti EdgeMAX: киты охлаждения, SFP+ близость к радиатору CPU и SNMP hrDeviceTemperature, снижение IPSec burst, baffles стойки.',
            ' Ubiquiti EdgeMAX՝ հովացման կիտի նստվածություն, SFP+ և CPU ջերմափոխանակիչ, hrDeviceTemperature, IPSec burst, rack baffles։',
        ),
        'ubiquiti_unifi_ap': (
            ' Ubiquiti UniFi access point thermal guidance: verify ceiling tile clearance and metal ceiling reflection heating, reduce channel width temporarily to lower RF chain temperature, compare SNMP or controller thermal stats with site survey IR shots, and replace aging PoE injectors that sag voltage under thermal load.',
            ' UniFi AP: зазор потолка и отражение металла, временное сужение канала, SNMP/controller и ИК, замена старых PoE инжекторов с просадкой под нагревом.',
            ' UniFi AP՝ առաստաղի մաքուր տարածք, մետաղի արտացոլում, ալիքի լայնության նվազեցում, SNMP/controller և IR, PoE ինժեկտորների փոխարինում։',
        ),
        'vmware_esxi_snmp': (
            ' VMware ESXi host thermal remediation: validate C-state power policies, confirm IPMI or embedded BMC pass-through readings against ESXi SNMP hrDeviceTemperature, evacuate VMs selectively to drop package power, and inspect DIMM channel population balance before requesting hardware vendor onsite.',
            ' VMware ESXi: политики C-state, IPMI/BMC и SNMP hrDeviceTemperature, эвакуация VM для снижения мощности пакета, баланс каналов DIMM перед вызовом вендора.',
            ' VMware ESXi՝ C-state քաղաքականություններ, IPMI/BMC և hrDeviceTemperature, ընտրովի VM էվակուացիա, DIMM ալիքների բаланս։',
        ),
        'netapp_ontap_snmp': (
            ' NetApp ONTAP thermal and airflow: correlate shelf PSU fan SNMP env thresholds with controller module inlet sensors, verify disk shelf cable management for lateral exhaust, check NVMe drive carrier blanking, and schedule aggregate rebalancing only after cooling margins recover.',
            ' NetApp ONTAP: PSU вентиляторы полок и inlet контроллеров, кабельный менеджмент полок, заглушки NVMe carriers, rebalance агрегатов после запаса по охлаждению.',
            ' NetApp ONTAP՝ shelf PSU հովացուցիչներ և controller inlet, մալուխի կառավարում, NVMe carrier blanking, aggregate rebalance։',
        ),
        'synology_dsm': (
            ' Synology DSM thermal playbook: validate fan speed SNMP synoSystemfanSpeed against dust loading, confirm expansion unit intake filters, pause BTRFS scrub during heat events, and stagger snapshot replication jobs until synoSystemStatus returns healthy.',
            ' Synology DSM: SNMP synoSystemfanSpeed и пыль, фильтры expansion, пауза BTRFS scrub при жаре, отложить репликацию до synoSystemStatus healthy.',
            ' Synology DSM՝ synoSystemfanSpeed և փոշի, expansion ֆիլտրներ, BTRFS scrub դադար, replication հետաձգում մինչև synoSystemStatus healthy։',
        ),
        'generic_linux_net_snmp': (
            ' Linux server thermal remediation via net-snmp UCD-SNMP-MIB context: verify lmSensors alignment with physical probes, clean CPU heatsinks and case filters, confirm liquid cooling pump tach if present, validate rack door perforation compliance, and capture dmidecode thermal metadata during maintenance.',
            ' Linux net-snmp: согласование lmSensors с физическими датчиками, чистка радиаторов и фильтров, тах помпы ЖО, перфорация дверей стойки, dmidecode в окне обслуживания.',
            ' Linux net-snmp՝ lmSensors համաձայնեցում ֆիզիկական սենսորների հետ, ջերմափոխանակիչների մաքրում, հեղուկային պոմպի tach, արկային դռների պերֆորացիա, dmidecode։',
        ),
        'generic_windows_snmp': (
            ' Windows Server SNMP thermal remediation: compare Microsoft SNMP Host Resources hrDeviceTemperature with WMI MSAcpi_ThermalZoneTemperature when available, validate chassis intrusion and fan failure event logs, confirm BIOS fan curves after firmware updates, and align workload bursts with HVAC seasonal setpoints.',
            ' Windows Server SNMP: hrDeviceTemperature и WMI MSAcpi_ThermalZoneTemperature, журналы вентиляторов и вскрытия, кривые вентиляторов BIOS после FW, пики нагрузки и HVAC setpoint.',
            ' Windows Server SNMP՝ hrDeviceTemperature և WMI MSAcpi_ThermalZoneTemperature, հովացուցիչների և ներխուժման մատյաններ, BIOS fan curves, HVAC setpoint։',
        ),
    }
    pack = bank.get(vt) or bank['generic_linux_net_snmp']
    return _localize(language, pack[0], pack[1], pack[2])


def _get_issue_key(device):
    macros = _macro_thresholds(str(device.get('vendor_template') or 'generic_linux_net_snmp'))
    cpu_max = int(macros.get('CPU_UTIL_MAX', 90))
    ram_max = int(macros.get('MEMORY_UTIL_MAX', macros.get('RAM_UTIL_MAX', 90)))
    disk_max = int(macros.get('DISK_UTIL_MAX', 95))
    temp_max = int(macros.get('TEMP_C_MAX', 80))
    if str(device.get('status')) == 'offline':
        return 'OFFLINE'
    temp_raw = device.get('temperature_c')
    if temp_raw is not None and int(temp_raw) >= temp_max:
        return 'HIGH_TEMP'
    disk_raw = device.get('disk_usage')
    if disk_raw is not None and int(disk_raw) > disk_max:
        return 'DISK_FULL'
    ram_raw = device.get('ram_usage')
    if ram_raw is not None and int(ram_raw) > ram_max:
        return 'HIGH_RAM'
    cpu_raw = device.get('cpu_utilization')
    if cpu_raw is not None and int(cpu_raw) > cpu_max:
        return 'HIGH_CPU'
    return 'NORMAL'


def generate_snmp_device_recommendations(connection, snmp_metrics, target_language='en', maximum_matches=5):
    language = target_language if target_language in ('en', 'ru', 'hy') else 'en'
    docs, metadata = _load_hardware_playbooks_and_manuals(connection, language)
    if not docs:
        return []
    vectorizer = TfidfVectorizer(max_features=4096, ngram_range=(1, 2))
    matrix = vectorizer.fit_transform(docs)
    recommendations = []
    for device in snmp_metrics or []:
        issue_key = _get_issue_key(device)
        if issue_key == 'NORMAL':
            continue
        if issue_key == 'HIGH_TEMP' and int(device.get('cpu_utilization') or 0) >= 95:
            custom_text = _localize(
                language,
                f"{device.get('hostname', 'Device')} temp is critical. Needs physical cleaning or thermal paste replacement.",
                f"У {device.get('hostname', 'Device')} критическая температура. Требуется физическая очистка или замена термопасты.",
                f"{device.get('hostname', 'Device')} սարքի ջերմաստիճանը կրիտիկական է։ Պահանջվում է ֆիզիկական մաքրում կամ թերմոպաստայի փոխարինում։",
            )
            custom_text = (custom_text + _vendor_thermal_clause(device.get('vendor_template'), language)).strip()
            recommendations.append(
                {
                    'device': device.get('hostname'),
                    'ip': device.get('ip'),
                    'issue_key': issue_key,
                    'title': _localize(language, 'Critical temperature with high CPU', 'Критическая температура и высокий CPU', 'Կրիտիկական ջերմաստիճան և բարձր CPU'),
                    'resolution_steps': custom_text,
                    'similarity_score': 1.0,
                }
            )
            continue
        query = build_query_text_from_snmp_metrics([device]) + ' ' + issue_key.lower().replace('_', ' ')
        query_vector = vectorizer.transform([query])
        similarity_scores = cosine_similarity(query_vector, matrix).flatten()
        if len(similarity_scores) == 0:
            continue
        best_index = int(np.argmax(similarity_scores))
        best_metadata = metadata[best_index]
        resolution_body = str(device.get('hostname')) + ': ' + best_metadata['remediation']
        if issue_key == 'HIGH_TEMP':
            resolution_body = (resolution_body + _vendor_thermal_clause(device.get('vendor_template'), language)).strip()
        recommendations.append(
            {
                'device': device.get('hostname'),
                'ip': device.get('ip'),
                'issue_key': issue_key,
                'title': best_metadata['title'],
                'resolution_steps': resolution_body,
                'similarity_score': float(similarity_scores[best_index]),
            }
        )
    recommendations.sort(key=lambda item: item.get('similarity_score', 0.0), reverse=True)
    return recommendations[:maximum_matches]


def calculate_global_health_score(snmp_metrics):
    score_value = 100
    for device in snmp_metrics or []:
        if str(device.get('status')) == 'offline':
            score_value -= 10
            continue
        macros = _macro_thresholds(str(device.get('vendor_template') or 'generic_linux_net_snmp'))
        cpu_max = int(macros.get('CPU_UTIL_MAX', 90))
        ram_max = int(macros.get('MEMORY_UTIL_MAX', macros.get('RAM_UTIL_MAX', 90)))
        disk_max = int(macros.get('DISK_UTIL_MAX', 95))
        temp_max = int(macros.get('TEMP_C_MAX', 80))
        cpu_raw = device.get('cpu_utilization')
        if cpu_raw is not None and int(cpu_raw) > cpu_max:
            score_value -= 2
        ram_raw = device.get('ram_usage')
        if ram_raw is not None and int(ram_raw) > ram_max:
            score_value -= 2
        temp_raw = device.get('temperature_c')
        if temp_raw is not None and int(temp_raw) >= temp_max:
            score_value -= 5
        disk_raw = device.get('disk_usage')
        if disk_raw is not None and int(disk_raw) > disk_max:
            score_value -= 5
    if score_value < 0:
        return 0
    if score_value > 100:
        return 100
    return int(score_value)


def generate_global_ai_recommendation(global_health_score, snmp_metrics, target_language='en'):
    language = target_language if target_language in ('en', 'ru', 'hy') else 'en'
    high_cpu_count = 0
    high_temp_count = 0
    for device in snmp_metrics or []:
        if str(device.get('status', '')).lower() == 'offline':
            continue
        cpu_raw = device.get('cpu_utilization')
        if cpu_raw is not None and int(cpu_raw) > 85:
            high_cpu_count += 1
        temp_raw = device.get('temperature_c')
        if temp_raw is not None and int(temp_raw) >= 80:
            high_temp_count += 1
    if global_health_score >= 95:
        return _localize(
            language,
            f"Overall health is {global_health_score}%. Infrastructure is stable with minor optimization opportunities.",
            f"Общее состояние {global_health_score}%. Инфраструктура стабильна, возможны точечные оптимизации.",
            f"Ընդհանուր առողջությունը {global_health_score}% է։ Ենթակառուցվածքը կայուն է, կան փոքր օպտիմիզացիայի հնարավորություններ։",
        )
    if global_health_score >= 90:
        return _localize(
            language,
            f"Overall health is {global_health_score}%. Recommend scaling out database servers to reduce CPU load across the cluster.",
            f"Общее состояние {global_health_score}%. Рекомендуется масштабировать серверы баз данных для снижения CPU-нагрузки по кластеру.",
            f"Ընդհանուր առողջությունը {global_health_score}% է։ Խորհուրդ է տրվում մասշտաբավորել տվյալների բազայի սերվերները՝ կլաստերի CPU բեռը նվազեցնելու համար։",
        )
    return _localize(
        language,
        f"Overall health is {global_health_score}%. Immediate capacity and hardware intervention is required. High CPU nodes: {high_cpu_count}, high temperature nodes: {high_temp_count}.",
        f"Общее состояние {global_health_score}%. Требуется немедленное вмешательство по емкости и оборудованию. Узлов с высоким CPU: {high_cpu_count}, узлов с высокой температурой: {high_temp_count}.",
        f"Ընդհանուր առողջությունը {global_health_score}% է։ Անհրաժեշտ է անհապաղ միջամտություն հզորության և ապարատային մասում։ Բարձր CPU ունեցող հանգույցներ՝ {high_cpu_count}, բարձր ջերմաստիճան ունեցող հանգույցներ՝ {high_temp_count}։",
    )


def _fetch_metrics_history(connection, host_id, limit_value=5, oldest_first=False):
    cursor = connection.cursor()
    if oldest_first:
        cursor.execute(
            'SELECT status, cpu_utilization, ram_usage, disk_usage, temperature_c, mock_data, polled_at, latency_ms, http_status_code '
            'FROM metrics_history WHERE host_id = ? ORDER BY datetime(polled_at) ASC, id ASC LIMIT ?',
            (int(host_id), int(limit_value)),
        )
    else:
        cursor.execute(
            'SELECT status, cpu_utilization, ram_usage, disk_usage, temperature_c, mock_data, polled_at, latency_ms, http_status_code '
            'FROM metrics_history WHERE host_id = ? ORDER BY datetime(polled_at) DESC, id DESC LIMIT ?',
            (int(host_id), int(limit_value)),
        )
    rows = cursor.fetchall()
    history = []
    for status, cpu, ram, disk, temp, mock_data, polled_at, latency_ms, http_status_code in rows:
        history.append(
            {
                'status': str(status),
                'cpu_utilization': None if cpu is None else int(cpu),
                'ram_usage': None if ram is None else int(ram),
                'disk_usage': None if disk is None else int(disk),
                'temperature_c': None if temp is None else int(temp),
                'mock_data': bool(int(mock_data)),
                'polled_at': str(polled_at),
                'latency_ms': None if latency_ms is None else int(latency_ms),
                'http_status_code': None if http_status_code is None else int(http_status_code),
            }
        )
    return history


def _parse_polled_ts(raw_value):
    text_value = str(raw_value or '').strip()
    if not text_value:
        return None
    compact = text_value.replace('Z', '').split('+', 1)[0]
    formats = ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f')
    for fmt in formats:
        try:
            return datetime.strptime(compact[:26], fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(compact[:26])
    except ValueError:
        return None


def _forecast_linear_horizon(series_rows, metric_key, ceiling_value):
    if len(series_rows) < 5:
        return None
    points = []
    for row in series_rows:
        moment = _parse_polled_ts(row.get('polled_at'))
        if moment is None:
            continue
        raw_metric = row.get(metric_key)
        if raw_metric is None:
            continue
        points.append((moment, float(raw_metric)))
    if len(points) < 5:
        return None
    baseline = points[0][0]
    hours_numeric = [(moment - baseline).total_seconds() / 3600.0 for moment, _ in points]
    values_numeric = [value for _, value in points]
    slope, intercept = np.polyfit(np.array(hours_numeric, dtype=float), np.array(values_numeric, dtype=float), 1)
    slope_float = float(slope)
    if slope_float <= 0.08:
        return None
    last_hour = hours_numeric[-1]
    intercept_float = float(intercept)
    estimated_cross_hour = None
    if abs(slope_float) > 1e-9:
        estimated_cross_hour = (float(ceiling_value) - intercept_float) / slope_float
    if estimated_cross_hour is None:
        return None
    hours_remaining = estimated_cross_hour - last_hour
    peak_now = slope_float * last_hour + intercept_float
    if peak_now >= float(ceiling_value):
        return None
    if hours_remaining <= 0.2 or hours_remaining > 672:
        return None
    return slope_float, hours_remaining


def _format_predictive_text(language_value, hostname_value, metric_name, slope_value, hours_remaining_value):
    hours_rounded = max(round(float(hours_remaining_value), 1), 0.3)
    slope_rounded = round(float(slope_value), 3)
    return _localize(
        language_value,
        f'{metric_name} utilization on {hostname_value} is trending upward linearly at roughly {slope_rounded}% per hour versus recent samples. Prediction: critical envelope near {95}% approximately {hours_rounded} hours ahead if the slope persists. Evaluate batch windows, bursting limits, saturation on dependent datastore paths, then apply controlled mitigation.',
        f'{metric_name} на {hostname_value} почти линейно растёт примерно на {slope_rounded}% в час по последним выборкам. Прогноз: порог около {95}% примерно через {hours_rounded} часа при сохранении тренда. Проверьте пакетные окна, лимиты всплесков и узкие места хранилища, затем применяйте поэтапное смягчение риска.',
        f'{hostname_value}-ում {metric_name} փոխվում է մոտավորապես {slope_rounded}% յուր ժամ։ Կանխատեսման տակ շուրջ {hours_rounded} ժամում հնարավոր է մոտ {95}% օգտագործում առանց միջամտության։ Նախ զննեք workloads-ները և կախված համակարգերը, հետո զգույշ մեղմեք ռիսկը։',
    )


def compute_poll_sla_percent(connection, host_id_value):
    cursor = connection.cursor()
    cursor.execute(
        'SELECT COUNT(*), SUM(CASE WHEN lower(trim(status)) != \'offline\' THEN 1 ELSE 0 END) FROM metrics_history WHERE host_id = ?',
        (int(host_id_value),),
    )
    row = cursor.fetchone()
    if not row or int(row[0] or 0) <= 0:
        return 100.0
    total = int(row[0])
    ok = int(row[1] or 0)
    return round(100.0 * float(ok) / float(total), 2)


def _resource_exhaustion_day_messages(language_value, hostname_value, history_chronological):
    fragments = []
    for metric_key, label_en, label_ru, label_hy in (
        ('disk_usage', 'Disk', 'Диск', 'Սկավառակ'),
        ('ram_usage', 'RAM', 'ОЗУ', 'RAM'),
    ):
        horizon = _forecast_linear_horizon(history_chronological, metric_key, 100.0)
        if horizon is None:
            continue
        _slope_unused, hours_remaining_value = horizon
        days_estimate = max(float(hours_remaining_value) / 24.0, 0.2)
        day_rounded = max(int(round(days_estimate)), 1)
        fragments.append(
            _localize(
                language_value,
                f'Exhaustion warning: {label_en} space on {hostname_value} may reach 100% in approximately {day_rounded} days at the observed linear growth rate.',
                f'Предупреждение исчерпания: {label_ru} на {hostname_value} может достичь 100% примерно за {day_rounded} дней при текущем линейном росте.',
                f'Թողքի զգուշացում՝ {label_hy}-ը {hostname_value}-ում կարող է հասնել 100%-ի մոտավորապես {day_rounded} օրում դիտարկված գծային աճի դեպքում։',
            )
        )
    return ' '.join(fragments).strip()


def match_vulnerability_advisories(connection, scanner_payload, target_language='en'):
    normalized_language_value = target_language if target_language in ('en', 'ru', 'hy') else 'en'
    blobs = []
    for listener_record in scanner_payload.get('listening_sockets', []):
        combined_fragment = ' '.join(
            [
                str(listener_record.get('service_guess', '')),
                str(listener_record.get('process_name', '')),
                str(listener_record.get('service_version_banner', '')),
                str(listener_record.get('protocol', '')),
                str(listener_record.get('port', '')),
            ]
        )
        blobs.append(normalize_free_text_for_matching(combined_fragment))
    flattened = normalize_free_text_for_matching(' '.join(blobs))
    cursor = connection.cursor()
    cursor.execute(
        'SELECT match_signature, cve_identifier, advice_en, advice_ru, advice_hy, powershell_script FROM vulnerability_playbooks'
    )
    advisories_output = []
    for match_signature, cve_identifier, advice_en_value, advice_ru_value, advice_hy_value, powershell_script_value in cursor.fetchall():
        signature_normalized = normalize_free_text_for_matching(match_signature)
        if not signature_normalized or signature_normalized not in flattened:
            continue
        localized_advice_text = (
            advice_ru_value
            if normalized_language_value == 'ru'
            else advice_hy_value
            if normalized_language_value == 'hy'
            else advice_en_value
        )
        formatted_title = (
            f'{cve_identifier} :: {localized_advice_text[:220]}'
            if len(localized_advice_text) > 220
            else f'{cve_identifier} :: {localized_advice_text}'
        )
        advisories_output.append(
            {
                'cve_identifier': str(cve_identifier),
                'advice': localized_advice_text,
                'match_signature': str(match_signature),
                'powershell_script': str(powershell_script_value),
                'title': formatted_title,
            }
        )
    return advisories_output


def _collect_dependency_pressure_hint(connection, language_value, dependent_host_id, hostname_value):
    cursor = connection.cursor()
    cursor.execute(
        '''SELECT sd.depends_on_host_id, h.hostname FROM service_dependencies sd '''
        '''JOIN hosts h ON h.id = sd.depends_on_host_id '''
        '''WHERE sd.dependent_host_id = ?''',
        (int(dependent_host_id),),
    )
    rows = cursor.fetchall()
    if not rows:
        return '', ''
    segments = []
    database_connection_script_value = '$ProgressPreference = \'SilentlyContinue\'; netstat -ano | Select-String "5432|3306"'
    strained_present = False
    for upstream_id, upstream_hostname in rows:
        cursor.execute(
            'SELECT cpu_utilization, ram_usage, disk_usage, status FROM metrics_history WHERE host_id = ? '
            'ORDER BY datetime(polled_at) DESC, id DESC LIMIT 1',
            (int(upstream_id),),
        )
        upstream_row = cursor.fetchone()
        if not upstream_row:
            strained_present = True
            segments.append(
                _localize(
                    language_value,
                    f'Mapped datastore dependency {upstream_hostname} has no polled samples yet.',
                    f'Привязанная база данных {upstream_hostname} пока без свежего опроса.',
                    f'Կապված տվյալների բազա {upstream_hostname}-ը առայժմ չունի թարմ հարցումներ։',
                )
            )
            continue
        upstream_cpu_value, upstream_ram_value, upstream_disk_value, upstream_status = upstream_row
        upstream_cpu_int = int(upstream_cpu_value or 0)
        upstream_ram_int = int(upstream_ram_value or 0)
        upstream_disk_int = int(upstream_disk_value or 0)
        strained_flags = []
        if str(upstream_status) == 'offline':
            strained_flags.append('offline')
        if upstream_cpu_int >= 80:
            strained_flags.append(f'CPU {upstream_cpu_int}%')
        if upstream_ram_int >= 82:
            strained_flags.append(f'RAM {upstream_ram_int}%')
        if upstream_disk_int >= 92:
            strained_flags.append(f'DISK {upstream_disk_int}%')
        if not strained_flags:
            continue
        strained_present = True
        fragments_joined = ', '.join(strained_flags)
        segments.append(
            _localize(
                language_value,
                f'Dependency {upstream_hostname} is showing pressure ({fragments_joined}); {hostname_value} may inherit latency or exhaustion symptoms on that datastore path.',
                f'Зависимость {upstream_hostname} демонстрирует давление ({fragments_joined}); {hostname_value} может унаследовать задержки или перегруз памяти на этом пути к хранилищу.',
                f'Կախվածություն {upstream_hostname}-ը ընդգծում է ճնշում ({fragments_joined})؛ {hostname_value}-ը կարող է զգալ ուշացում կամ պատուհանումներ տվյալների պահուստավոր ուղղությամբ։',
            )
        )
    if not strained_present:
        return '', ''
    return ' '.join(segments).strip(), database_connection_script_value


def _combine_predictive_signals(language_value, hostname_value, history_chronological, device_kind, vendor_template=None):
    if str(device_kind) == 'Website':
        return ''
    macros = _macro_thresholds(str(vendor_template or 'generic_linux_net_snmp'))
    cpu_cut = int(macros.get('CPU_UTIL_MAX', 95))
    ram_cut = int(macros.get('MEMORY_UTIL_MAX', macros.get('RAM_UTIL_MAX', 92)))
    disk_cut = int(macros.get('DISK_UTIL_MAX', 95))
    temp_cut = int(macros.get('TEMP_C_MAX', 80))
    prioritized_strings = []
    metric_definitions = [('cpu_utilization', 'CPU', cpu_cut)]
    if str(device_kind) not in ('VM', 'Website'):
        metric_definitions.append(('temperature_c', 'Thermal edge', temp_cut))
    metric_definitions.extend([('ram_usage', 'RAM', ram_cut), ('disk_usage', 'Disk', disk_cut)])
    for metric_key_loop, readable_label, cutoff_value in metric_definitions:
        horizon_payload = _forecast_linear_horizon(history_chronological, metric_key_loop, cutoff_value)
        if not horizon_payload:
            continue
        slope_part, horizon_part = horizon_payload
        prioritized_strings.append(_format_predictive_text(language_value, hostname_value, readable_label, slope_part, horizon_part))
    if not prioritized_strings:
        return ''
    return prioritized_strings[0]


def _detect_website_trend_issue(history_rows):
    if not history_rows:
        return 'NORMAL', {}
    samples = len(history_rows)
    offline_count = sum(1 for r in history_rows if str(r.get('status')) == 'offline')
    bad_http = sum(
        1
        for r in history_rows
        if r.get('http_status_code') is not None
        and (int(r['http_status_code']) < 200 or int(r['http_status_code']) >= 400)
    )
    latency_series = [int(r['latency_ms']) for r in history_rows if r.get('latency_ms') is not None]
    latency_spike_flag = False
    baseline_latency = 0.0
    latest_latency = 0
    delta_latency = 0.0
    if len(latency_series) >= 4:
        latest_latency = int(latency_series[0])
        baseline_vals = [int(v) for v in latency_series[1:11]]
        if baseline_vals:
            baseline_latency = sum(baseline_vals) / float(len(baseline_vals))
            delta_latency = float(latest_latency) - baseline_latency
            if delta_latency >= 500.0 and latest_latency >= max(800.0, baseline_latency + 200.0):
                latency_spike_flag = True
    trend = {
        'samples': samples,
        'offline_count': offline_count,
        'bad_http': bad_http,
        'latency_spike': 1 if latency_spike_flag else 0,
        'baseline_latency': baseline_latency,
        'latest_latency': latest_latency,
        'delta_latency': delta_latency,
    }
    if offline_count >= 2:
        return 'OFFLINE', trend
    if bad_http >= 1:
        return 'HTTP_STATUS_ERROR', trend
    if latency_spike_flag:
        return 'LATENCY_SPIKE', trend
    return 'NORMAL', trend


def _detect_trend_issue(history_rows, canonical_device_kind='Server', vendor_template=None):
    if not history_rows:
        return 'NORMAL', {}
    if str(canonical_device_kind) == 'Website':
        return _detect_website_trend_issue(history_rows)
    macros = _macro_thresholds(str(vendor_template or 'generic_linux_net_snmp'))
    cpu_cut = int(macros.get('CPU_UTIL_MAX', 90))
    ram_cut = int(macros.get('MEMORY_UTIL_MAX', macros.get('RAM_UTIL_MAX', 90)))
    disk_cut = int(macros.get('DISK_UTIL_MAX', 95))
    temp_cut = int(macros.get('TEMP_C_MAX', 80))
    offline_count = sum(1 for r in history_rows if str(r.get('status')) == 'offline')
    cpu_spikes = sum(1 for r in history_rows if int(r.get('cpu_utilization') or 0) > cpu_cut)
    ram_spikes = sum(1 for r in history_rows if int(r.get('ram_usage') or 0) > ram_cut)
    temp_spikes = sum(1 for r in history_rows if int(r.get('temperature_c') or 0) >= temp_cut)
    if canonical_device_kind == 'VM':
        temp_spikes = 0
    disk_spikes = sum(1 for r in history_rows if int(r.get('disk_usage') or 0) > disk_cut)
    trend = {
        'samples': len(history_rows),
        'offline_count': offline_count,
        'cpu_spikes': cpu_spikes,
        'ram_spikes': ram_spikes,
        'temp_spikes': temp_spikes,
        'disk_spikes': disk_spikes,
    }
    if offline_count >= 2:
        return 'OFFLINE', trend
    if temp_spikes >= 2:
        return 'HIGH_TEMP', trend
    if disk_spikes >= 2:
        return 'DISK_FULL', trend
    if ram_spikes >= 2:
        return 'HIGH_RAM', trend
    if cpu_spikes >= 3:
        return 'HIGH_CPU', trend
    return 'NORMAL', trend


def _format_trend_text(language, hostname, issue_key, trend):
    samples = int(trend.get('samples', 0))
    if issue_key == 'HIGH_CPU':
        return _localize(
            language,
            f"{hostname} shows recurring high CPU pressure in {trend.get('cpu_spikes', 0)}/{samples} recent polls versus the template CPU threshold. This is a trend, not a one-off spike.",
            f"На {hostname} наблюдается повторяющееся высокое давление на CPU в {trend.get('cpu_spikes', 0)}/{samples} последних опросов относительно порога шаблона. Это тренд.",
            f"{hostname} սարքի մոտ կրկնվող բարձր CPU ճնշում է {trend.get('cpu_spikes', 0)}/{samples} վերջին հարցումներում՝ համեմատած ձևանմուշի շեմի հետ։ Սա միտում է։",
        )
    if issue_key == 'HIGH_RAM':
        return _localize(
            language,
            f"{hostname} shows recurring high RAM utilization in {trend.get('ram_spikes', 0)}/{samples} recent polls versus the template memory threshold.",
            f"На {hostname} повторяется высокая утилизация RAM в {trend.get('ram_spikes', 0)}/{samples} последних опросов относительно порога памяти шаблона.",
            f"{hostname} սարքի մոտ կրկնվում է RAM-ի բարձր օգտագործում {trend.get('ram_spikes', 0)}/{samples} վերջին հարցումներում՝ հիշողության ձևանմուշային շեմի նկատմամբ։",
        )
    if issue_key == 'HIGH_TEMP':
        return _localize(
            language,
            f"{hostname} shows recurring critical temperature in {trend.get('temp_spikes', 0)}/{samples} recent polls. Treat as sustained thermal risk.",
            f"На {hostname} наблюдается повторяющаяся критическая температура в {trend.get('temp_spikes', 0)}/{samples} последних опросов. Рассматривайте это как устойчивый тепловой риск.",
            f"{hostname} սարքի մոտ կրկնվող կրիտիկական ջերմաստիճան է {trend.get('temp_spikes', 0)}/{samples} վերջին հարցումներում։ Դիտարկեք որպես կայուն ջերմային ռիսկ։",
        )
    if issue_key == 'DISK_FULL':
        return _localize(
            language,
            f"{hostname} shows repeated disk critical usage in {trend.get('disk_spikes', 0)}/{samples} recent polls. Capacity pressure is persistent.",
            f"На {hostname} повторяется критическое заполнение диска в {trend.get('disk_spikes', 0)}/{samples} последних опросов. Давление по емкости устойчивое.",
            f"{hostname} սարքի մոտ կրկնվում է սկավառակի կրիտիկական օգտագործումը {trend.get('disk_spikes', 0)}/{samples} վերջին հարցումներում։ Տարողության ճնշումը կայուն է։",
        )
    if issue_key == 'OFFLINE':
        return _localize(
            language,
            f"{hostname} is repeatedly unreachable in {trend.get('offline_count', 0)}/{samples} recent polls. Investigate power/network stability.",
            f"У {hostname} часто наблюдается недоступность в {trend.get('offline_count', 0)}/{samples} последних опросов. Проверьте питание и стабильность сети.",
            f"{hostname}-ը անհամապատասխան հասանելի է եղել {trend.get('offline_count', 0)}/{samples} վերջին հարցումներում։ Ստուգեք սնուցումը և ցանցը։",
        )
    if issue_key == 'LATENCY_SPIKE':
        delta_rounded = int(round(float(trend.get('delta_latency') or 0.0)))
        return _localize(
            language,
            f"{hostname} is responding about {delta_rounded} ms slower than the recent baseline (latest {int(trend.get('latest_latency') or 0)} ms vs baseline near {round(float(trend.get('baseline_latency') or 0.0), 1)} ms).",
            f"{hostname} отвечает примерно на {delta_rounded} мс медленнее недавнего базового уровня (последнее {int(trend.get('latest_latency') or 0)} мс против базы около {round(float(trend.get('baseline_latency') or 0.0), 1)} мс).",
            f"{hostname}-ը մոտավորապես {delta_rounded} մս ավելի դանդաղ է պատասխանում վերջին բազային մակարդակից (վերջինը {int(trend.get('latest_latency') or 0)} մս, բազան մոտ {round(float(trend.get('baseline_latency') or 0.0), 1)} մս)։",
        )
    if issue_key == 'HTTP_STATUS_ERROR':
        return _localize(
            language,
            f"{hostname} returned an abnormal HTTP status in recent checks (non-success class). Validate routing, certificates, and upstream application health.",
            f"У {hostname} зафиксированы аномальные HTTP-коды в последних проверках (вне класса успеха). Проверьте маршрутизацию, сертификаты и состояние приложения.",
            f"{hostname}-ը վերջին ստուգումներում վերադարձրել է աննորմալ HTTP կարգավիճակ (ոչ հաջողության դաս)։ Ստուգեք երթուղին, վկայագրերը և հավելվածի առողջությունը։",
        )
    return ''


def compute_predictive_utilization_anomaly(connection, host_id):
    cursor = connection.cursor()
    cursor.execute(
        'SELECT COALESCE(vendor_template, ?) FROM hosts WHERE id = ? LIMIT 1',
        ('generic_linux_net_snmp', int(host_id)),
    )
    vendor_row = cursor.fetchone()
    vendor_key = str(vendor_row[0] or 'generic_linux_net_snmp') if vendor_row else 'generic_linux_net_snmp'
    macros = _macro_thresholds(vendor_key)
    cpu_thr = int(macros.get('CPU_UTIL_MAX', 90))
    ram_thr = int(macros.get('MEMORY_UTIL_MAX', macros.get('RAM_UTIL_MAX', 90)))
    cursor.execute(
        'SELECT status, cpu_utilization, ram_usage FROM metrics_history WHERE host_id = ? '
        'ORDER BY datetime(polled_at) DESC, id DESC LIMIT 11',
        (int(host_id),),
    )
    rows = cursor.fetchall()
    if len(rows) < 2:
        return {'active': False}
    if str(rows[0][0]).lower() == 'offline':
        return {'active': False}
    latest_cpu = int(rows[0][1] or 0)
    latest_ram = int(rows[0][2] or 0)
    prior_rows = rows[1:11]
    if not prior_rows:
        return {'active': False}
    cpu_values = [int(r[1] or 0) for r in prior_rows]
    ram_values = [int(r[2] or 0) for r in prior_rows]
    cpu_avg = sum(cpu_values) / float(len(cpu_values))
    ram_avg = sum(ram_values) / float(len(ram_values))
    cpu_spike = False
    ram_spike = False
    if cpu_avg >= 1.0:
        cpu_spike = latest_cpu > cpu_avg * 1.25 and latest_cpu > cpu_thr
    else:
        cpu_spike = latest_cpu > cpu_thr
    if ram_avg >= 1.0:
        ram_spike = latest_ram > ram_avg * 1.25 and latest_ram > ram_thr
    else:
        ram_spike = latest_ram > ram_thr
    active_flag = cpu_spike or ram_spike
    cpu_pct_above = 0.0
    ram_pct_above = 0.0
    if cpu_avg >= 1.0 and latest_cpu > cpu_avg:
        cpu_pct_above = (latest_cpu - cpu_avg) / cpu_avg * 100.0
    if ram_avg >= 1.0 and latest_ram > ram_avg:
        ram_pct_above = (latest_ram - ram_avg) / ram_avg * 100.0
    return {
        'active': active_flag,
        'cpu_spike': cpu_spike,
        'ram_spike': ram_spike,
        'latest_cpu': latest_cpu,
        'latest_ram': latest_ram,
        'cpu_avg': cpu_avg,
        'ram_avg': ram_avg,
        'cpu_pct_above': cpu_pct_above,
        'ram_pct_above': ram_pct_above,
    }


def compute_website_endpoint_anomaly(connection, host_id):
    cursor = connection.cursor()
    cursor.execute(
        'SELECT status, latency_ms, http_status_code FROM metrics_history WHERE host_id = ? '
        'ORDER BY datetime(polled_at) DESC, id DESC LIMIT 12',
        (int(host_id),),
    )
    rows = cursor.fetchall()
    if not rows:
        return {'active': False}
    if str(rows[0][0]).lower() == 'offline':
        return {'active': False}
    latest_latency = rows[0][1]
    latest_http = rows[0][2]
    http_error = False
    if latest_http is not None:
        code_int = int(latest_http)
        if code_int < 200 or code_int >= 400:
            http_error = True
    latency_spike = False
    delta_ms = 0.0
    baseline_latency = 0.0
    latest_latency_int = 0
    latency_rows = [r for r in rows if r[1] is not None]
    if len(latency_rows) >= 2:
        latest_latency_int = int(latency_rows[0][1])
        prior_vals = [int(r[1]) for r in latency_rows[1:12]]
        if prior_vals:
            baseline_latency = sum(prior_vals) / float(len(prior_vals))
            delta_ms = float(latest_latency_int) - baseline_latency
            if delta_ms >= 500.0 and latest_latency_int >= max(800.0, baseline_latency + 200.0):
                latency_spike = True
    active_flag = http_error or latency_spike
    return {
        'active': active_flag,
        'latency_spike': latency_spike,
        'http_error': http_error,
        'latest_latency': int(latest_latency) if latest_latency is not None else None,
        'latency_avg': baseline_latency,
        'delta_ms': delta_ms,
        'http_status_code': int(latest_http) if latest_http is not None else None,
        'cpu_spike': False,
        'ram_spike': False,
        'latest_cpu': 0,
        'latest_ram': 0,
        'cpu_avg': 0.0,
        'ram_avg': 0.0,
        'cpu_pct_above': 0.0,
        'ram_pct_above': 0.0,
    }


def _format_predictive_ui_message(language, state):
    if not state.get('active'):
        return ''
    if state.get('http_error') or state.get('latency_spike'):
        fragments = []
        if state.get('latency_spike'):
            delta_display = int(round(float(state.get('delta_ms') or 0.0)))
            fragments.append(
                _localize(
                    language,
                    'Endpoint alert: response latency is about '
                    + str(delta_display)
                    + ' ms above the rolling baseline.',
                    'Точка опроса: задержка ответа примерно на '
                    + str(delta_display)
                    + ' мс выше скользящего базового уровня.',
                    'Կետային զգուշացում. պատասխանի ուշացումը մոտ '
                    + str(delta_display)
                    + ' մս-ով բարձր է սահող բազայից։',
                )
            )
        if state.get('http_error'):
            code_piece = str(state.get('http_status_code') or '')
            fragments.append(
                _localize(
                    language,
                    'Endpoint alert: latest HTTP status code ' + code_piece + ' is outside the success range.',
                    'Точка опроса: последний HTTP-код ' + code_piece + ' вне диапазона успешных ответов.',
                    'Կետային զգուշացում. վերջին HTTP կոդը ' + code_piece + ' հաջողության տիրույթից դուրս է։',
                )
            )
        return ' '.join(fragments).strip()
    fragments = []
    if state.get('cpu_spike'):
        pct_display = round(float(state.get('cpu_pct_above') or 0.0), 1)
        fragments.append(
            _localize(
                language,
                'Predictive Alert: CPU usage is '
                + str(pct_display)
                + '% above the historical rolling average.',
                'Прогноз: CPU на '
                + str(pct_display)
                + '% выше скользящего среднего по истории.',
                'Կանխատեսման զգուշացում. CPU-ն '
                + str(pct_display)
                + '%-ով բարձր է պատմական սահող միջինից։',
            )
        )
    if state.get('ram_spike'):
        pct_display = round(float(state.get('ram_pct_above') or 0.0), 1)
        fragments.append(
            _localize(
                language,
                'Predictive Alert: RAM usage is '
                + str(pct_display)
                + '% above the historical rolling average.',
                'Прогноз: RAM на '
                + str(pct_display)
                + '% выше скользящего среднего по истории.',
                'Կանխատեսման զգուշացում. RAM-ը '
                + str(pct_display)
                + '%-ով բարձր է պատմական սահող միջինից։',
            )
        )
    return ' '.join(fragments).strip()


def _format_predictive_telegram_message(hostname, ip_address, state):
    lines = ['Predictive anomaly', str(hostname), str(ip_address)]
    if state.get('latency_spike'):
        lines.append(
            'Latency latest='
            + str(state.get('latest_latency'))
            + ' delta_ms='
            + str(int(round(float(state.get('delta_ms') or 0.0))))
            + ' baseline='
            + str(round(float(state.get('latency_avg') or 0.0), 2))
        )
    if state.get('http_error'):
        lines.append('HTTP status=' + str(state.get('http_status_code')))
    if state.get('cpu_spike'):
        lines.append('CPU latest=' + str(state.get('latest_cpu')) + ' avg10=' + str(round(float(state.get('cpu_avg') or 0.0), 2)))
    if state.get('ram_spike'):
        lines.append('RAM latest=' + str(state.get('latest_ram')) + ' avg10=' + str(round(float(state.get('ram_avg') or 0.0), 2)))
    return '\n'.join(lines)


def notify_predictive_anomaly_after_poll(connection, host_id, hostname, ip_address, db_path=None):
    cursor = connection.cursor()
    cursor.execute(
        'SELECT device_type, COALESCE(maintenance_mode, 0) FROM hosts WHERE id = ? LIMIT 1',
        (int(host_id),),
    )
    meta_row = cursor.fetchone()
    device_kind = str(meta_row[0] or 'Server') if meta_row else 'Server'
    maintenance_flag = int(meta_row[1] or 0) if meta_row else 0
    if maintenance_flag:
        return {'active': False}
    if device_kind == 'Website':
        state = compute_website_endpoint_anomaly(connection, int(host_id))
        if not state.get('active'):
            return state
        TelegramNotifier.send_alert(
            _format_predictive_telegram_message(str(hostname), str(ip_address), state),
            db_path,
            host_id=int(host_id),
            alert_type='website_endpoint',
        )
        return state
    state = compute_predictive_utilization_anomaly(connection, int(host_id))
    if not state.get('active'):
        return state
    TelegramNotifier.send_alert(
        _format_predictive_telegram_message(str(hostname), str(ip_address), state),
        db_path,
        host_id=int(host_id),
        alert_type='predictive_utilization',
    )
    return state


def generate_predictive_manual_suggestions(connection, target_language='en', maximum_results=12):
    language = target_language if target_language in ('en', 'ru', 'hy') else 'en'
    catalog_query = normalize_free_text_for_matching(
        'preventive maintenance reliability capacity planning degradation trend firmware validation redundancy '
        'runbook escalation containment lifecycle triage stabilize harden verify document observability drift'
    )
    docs, metadata = _load_hardware_playbooks_and_manuals(connection, language)
    if not docs:
        return []
    vectorizer = TfidfVectorizer(max_features=4096, ngram_range=(1, 2))
    matrix = vectorizer.fit_transform(docs)
    query_vector = vectorizer.transform([catalog_query])
    similarity_scores = cosine_similarity(query_vector, matrix).flatten()
    ranked_indices = np.argsort(-similarity_scores)
    output_rows = []
    for position in ranked_indices:
        if len(output_rows) >= int(maximum_results):
            break
        score_value = float(similarity_scores[int(position)])
        if score_value <= 0.01:
            continue
        meta_entry = metadata[int(position)]
        output_rows.append(
            {
                'source_key': str(meta_entry.get('issue_key', '')),
                'title': str(meta_entry.get('title', '')),
                'guidance': str(meta_entry.get('remediation', '')),
                'similarity_score': score_value,
            }
        )
    return output_rows


def generate_ai_decisions_from_metrics_history(connection, target_language='en', maximum_results=25):
    language = target_language if target_language in ('en', 'ru', 'hy') else 'en'
    cursor = connection.cursor()
    cursor.execute(
        'SELECT id, hostname, ip_address, device_type, COALESCE(vendor_template, ?), COALESCE(last_error_message, \'\') FROM hosts ORDER BY id',
        ('generic_linux_net_snmp',),
    )
    hosts = cursor.fetchall()
    docs, metadata = _load_hardware_playbooks_and_manuals(connection, language)
    vectorizer = TfidfVectorizer(max_features=4096, ngram_range=(1, 2))
    matrix = vectorizer.fit_transform(docs) if docs else None
    decisions = []
    for host_id_value, hostname_value, ip_address_value, device_kind, vendor_template_row, last_error_row in hosts:
        vendor_template_value = str(vendor_template_row or 'generic_linux_net_snmp')
        last_error_text = str(last_error_row or '').strip()
        history_descending = _fetch_metrics_history(connection, host_id_value, 40, oldest_first=False)
        history_ascending = _fetch_metrics_history(connection, host_id_value, 120, oldest_first=True)
        if history_descending and str(history_descending[0].get('status', '')).lower() == 'offline':
            unreachable_body = _localize(
                language,
                'DevAI CRITICAL: Host is completely unreachable. Verify network connectivity, power state, and firewall rules.',
                'DevAI КРИТИЧНО: Узел полностью недоступен. Проверьте сетевое подключение, питание и правила межсетевого экрана.',
                'DevAI ԿՐԻՏԻԿԱԿԱՆ. Հանգույցը ամբողջությամբ անհասանելի է։ Ստուգեք ցանցային կապը, սնուցումը և Firewall կանոնները։',
            )
            if last_error_text:
                unreachable_body = unreachable_body + ' DevAI diagnostic: ' + last_error_text
            unreachable_title = _localize(
                language,
                'CRITICAL: Host unreachable',
                'КРИТИЧНО: Узел недоступен',
                'ԿՐԻՏԻԿԱԿԱՆ. Հանգույցը անհասանելի է',
            )
            script_block_unreachable = _select_safe_script_snippet(str(device_kind), 'OFFLINE', '')
            decisions.append(
                {
                    'host_id': int(host_id_value),
                    'hostname': str(hostname_value),
                    'ip_address': str(ip_address_value),
                    'device_type': str(device_kind),
                    'vendor_template': vendor_template_value,
                    'issue_key': 'OFFLINE',
                    'title': unreachable_title,
                    'predictive_alert': False,
                    'trend_analysis': unreachable_body,
                    'predictive_projection': '',
                    'dependency_hints': '',
                    'resolution_text': '',
                    'script': script_block_unreachable.get('script'),
                    'script_language': script_block_unreachable.get('language'),
                    'similarity_score': 1.0,
                }
            )
            continue
        issue_key_primary, trend_struct = _detect_trend_issue(history_descending, str(device_kind), vendor_template_value)
        macro_lines = []
        if history_descending and str(history_descending[0].get('status', '')).lower() != 'offline':
            mchk = _macro_thresholds(vendor_template_value)
            cpu_m = int(mchk.get('CPU_UTIL_MAX', 90))
            ram_m = int(mchk.get('MEMORY_UTIL_MAX', mchk.get('RAM_UTIL_MAX', 90)))
            disk_m = int(mchk.get('DISK_UTIL_MAX', 95))
            temp_m = int(mchk.get('TEMP_C_MAX', 80))
            lx = history_descending[0]
            if lx.get('cpu_utilization') is not None and int(lx.get('cpu_utilization') or 0) > cpu_m:
                macro_lines.append(
                    _localize(
                        language,
                        'CRITICAL: Metric exceeded hardware-specific template threshold. CPU utilization is above the profile CPU_UTIL_MAX.',
                        'КРИТИЧНО: Показатель превысил порог шаблона оборудования. Загрузка CPU выше CPU_UTIL_MAX профиля.',
                        'ԿՐԻՏԻԿԱԿԱՆ։ Մետրիկան գերազանցեց սարքային ձևանմուշի շեմը։ CPU-ի օգտագործումը բարձր է profile CPU_UTIL_MAX-ից։',
                    )
                )
            if lx.get('ram_usage') is not None and int(lx.get('ram_usage') or 0) > ram_m:
                macro_lines.append(
                    _localize(
                        language,
                        'CRITICAL: Metric exceeded hardware-specific template threshold. RAM utilization is above the profile MEMORY_UTIL_MAX.',
                        'КРИТИЧНО: Показатель превысил порог шаблона оборудования. RAM выше MEMORY_UTIL_MAX профиля.',
                        'ԿՐԻՏԻԿԱԿԱՆ։ Մետրիկան գերազանցեց սարքային ձևանմուշի շեմը։ RAM-ը բարձր է profile MEMORY_UTIL_MAX-ից։',
                    )
                )
            if lx.get('disk_usage') is not None and int(lx.get('disk_usage') or 0) > disk_m:
                macro_lines.append(
                    _localize(
                        language,
                        'CRITICAL: Metric exceeded hardware-specific template threshold. Disk utilization is above the profile DISK_UTIL_MAX.',
                        'КРИТИЧНО: Показатель превысил порог шаблона оборудования. Диск выше DISK_UTIL_MAX профиля.',
                        'ԿՐԻՏԻԿԱԿԱՆ։ Մետրիկան գերազանցեց սարքային ձևանմուշի շեմը։ Սկավառակը բարձր է profile DISK_UTIL_MAX-ից։',
                    )
                )
            if (
                lx.get('temperature_c') is not None
                and str(device_kind) not in ('VM', 'Website')
                and int(lx.get('temperature_c') or 0) >= temp_m
            ):
                macro_lines.append(
                    _localize(
                        language,
                        'CRITICAL: Metric exceeded hardware-specific template threshold. Temperature is at or above the profile TEMP_C_MAX.',
                        'КРИТИЧНО: Показатель превысил порог шаблона оборудования. Температура достигла или выше TEMP_C_MAX профиля.',
                        'ԿՐԻՏԻԿԱԿԱՆ։ Մետրիկան գերազանցեց սարքային ձևանմուշի շեմը։ Ջերմաստիճանը հասել է կամ գերազանցել է profile TEMP_C_MAX-ին։',
                    )
                )
        macro_block = ' '.join(macro_lines).strip()
        is_website = str(device_kind) == 'Website'
        if is_website:
            predictive_state = compute_website_endpoint_anomaly(connection, int(host_id_value))
            predictive_ui = _format_predictive_ui_message(language, predictive_state) if predictive_state.get('active') else ''
            predictive_narrative = ''
            dependency_story, dependency_shell = '', ''
            exhaustion_fragment = ''
        else:
            predictive_state = compute_predictive_utilization_anomaly(connection, int(host_id_value))
            predictive_ui = _format_predictive_ui_message(language, predictive_state) if predictive_state.get('active') else ''
            predictive_narrative = _combine_predictive_signals(
                language, str(hostname_value), history_ascending, str(device_kind), vendor_template_value
            )
            dependency_story, dependency_shell = _collect_dependency_pressure_hint(
                connection, language, int(host_id_value), str(hostname_value)
            )
            exhaustion_fragment = _resource_exhaustion_day_messages(language, str(hostname_value), history_ascending)
        if (
            issue_key_primary == 'NORMAL'
            and not predictive_narrative
            and not dependency_story
            and not predictive_ui
            and not exhaustion_fragment
            and not macro_block
        ):
            continue
        trend_fragment = ''
        if issue_key_primary != 'NORMAL':
            trend_fragment = _format_trend_text(language, str(hostname_value), issue_key_primary, trend_struct)
        merged_narrative = ' '.join([macro_block, trend_fragment, predictive_narrative, dependency_story, exhaustion_fragment]).strip()
        if predictive_ui:
            merged_narrative = (predictive_ui + ' ' + merged_narrative).strip()
        tfidf_issue_token = issue_key_primary
        if macro_block and issue_key_primary == 'NORMAL':
            tfidf_issue_token = 'HIGH_CPU'
        if issue_key_primary == 'NORMAL' and predictive_narrative:
            tfidf_issue_token = 'HIGH_CPU'
        if is_website and issue_key_primary == 'NORMAL' and predictive_state.get('active'):
            if predictive_state.get('http_error'):
                tfidf_issue_token = 'HTTP_STATUS_ERROR'
            elif predictive_state.get('latency_spike'):
                tfidf_issue_token = 'LATENCY_SPIKE'
        if issue_key_primary == 'NORMAL' and dependency_story and not predictive_narrative:
            tfidf_issue_token = 'HIGH_CPU'
        query_payload = history_descending[:10] if history_descending else history_ascending[-10:]
        enriched_rows = [dict(row, vendor_template=vendor_template_value) for row in (query_payload or [])]
        query_text = normalize_free_text_for_matching(
            str(tfidf_issue_token)
            + ' '
            + vendor_template_value
            + ' '
            + build_query_text_from_snmp_metrics(enriched_rows)
            + ' '
            + merged_narrative
        )
        best_entry = {'title': tfidf_issue_token, 'remediation': '', 'remediation_script': ''}
        score_value = 0.0
        if matrix is not None and query_text.strip():
            query_vector = vectorizer.transform([query_text])
            similarity_scores = cosine_similarity(query_vector, matrix).flatten()
            best_index = int(np.argmax(similarity_scores)) if len(similarity_scores) else 0
            score_value = float(similarity_scores[best_index]) if len(similarity_scores) else 0.0
            if metadata:
                best_entry = dict(metadata[best_index])
        resolution_copy = str(best_entry.get('remediation') or '')
        if str(tfidf_issue_token) == 'HIGH_TEMP':
            resolution_copy = (resolution_copy + _vendor_thermal_clause(vendor_template_value, language)).strip()
        if predictive_narrative:
            score_value = max(score_value, 0.35)
        if dependency_story:
            score_value = max(score_value, 0.42)
        if predictive_state.get('active'):
            score_value = max(score_value, 0.55)
        if exhaustion_fragment:
            score_value = max(score_value, 0.48)
        if macro_block:
            score_value = max(score_value, 0.62)
        script_block = _select_safe_script_snippet(str(device_kind), tfidf_issue_token, best_entry.get('remediation_script', ''))
        if dependency_shell:
            base_script = str(script_block.get('script') or '').strip()
            stack_script = base_script + '\n\n' + dependency_shell if base_script else dependency_shell
            script_block['script'] = stack_script.strip()
        display_title = str(best_entry.get('title') or tfidf_issue_token)
        if predictive_state.get('active'):
            if is_website:
                display_title = (
                    _localize(language, 'Website endpoint alert', 'Предупреждение веб-конечной точки', 'Կայքի վերջնակետի զգուշացում')
                    + ' — '
                    + display_title
                )
            else:
                display_title = (
                    _localize(language, 'Predictive utilization alert', 'Прогноз утилизации', 'Կանխատեսվող օգտագործման զգուշացում')
                    + ' — '
                    + display_title
                )
        decisions.append(
            {
                'host_id': int(host_id_value),
                'hostname': str(hostname_value),
                'ip_address': str(ip_address_value),
                'device_type': str(device_kind),
                'vendor_template': vendor_template_value,
                'issue_key': str(tfidf_issue_token),
                'title': display_title,
                'predictive_alert': bool(predictive_state.get('active')),
                'trend_analysis': merged_narrative,
                'predictive_projection': predictive_narrative or '',
                'dependency_hints': dependency_story or '',
                'resolution_text': resolution_copy,
                'script': script_block.get('script'),
                'script_language': script_block.get('language'),
                'similarity_score': score_value,
            }
        )
    decisions.sort(key=lambda item: item.get('similarity_score', 0.0), reverse=True)
    return decisions[: int(maximum_results)]


def _select_safe_script_snippet(device_type, issue_key, fallback_script):
    normalized_type = str(device_type or '').strip().lower()
    if issue_key == 'LATENCY_SPIKE' and normalized_type == 'website':
        return {
            'language': 'powershell',
            'script': 'Measure-Command { Invoke-WebRequest -Uri https://example.com -UseBasicParsing -TimeoutSec 12 } | Select-Object -ExpandProperty TotalMilliseconds',
        }
    if issue_key == 'HTTP_STATUS_ERROR' and normalized_type == 'website':
        return {
            'language': 'powershell',
            'script': 'try { (Invoke-WebRequest -Uri https://example.com -UseBasicParsing -TimeoutSec 12).StatusCode } catch { $_.Exception.Response.StatusCode.value__ }',
        }
    if issue_key == 'HIGH_CPU':
        if normalized_type in ('server', 'vm', 'website'):
            return {
                'language': 'powershell',
                'script': 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 Name,CPU,Id',
            }
        return {'language': 'bash', 'script': 'systemctl restart nginx || true'}
    if issue_key == 'DISK_FULL':
        if normalized_type in ('server', 'vm', 'website'):
            return {
                'language': 'powershell',
                'script': 'Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free',
            }
        return {'language': 'bash', 'script': 'du -h -d 1 /var/log | sort -h | tail -n 20'}
    if issue_key == 'HIGH_TEMP':
        return {'language': 'powershell', 'script': 'Write-Output \'Review HVAC paths; capture thermal telemetry on site visit\''}
    if issue_key == 'OFFLINE':
        return {'language': 'powershell', 'script': 'Test-NetConnection -ComputerName 127.0.0.1 -Port 514'}
    script_value = str(fallback_script or '').strip()
    return {'language': 'bash', 'script': script_value} if script_value else {'language': 'bash', 'script': 'echo \"No script available\"'}


def vacuum_knowledge_database(db_path=None):
    connection = get_connection(db_path)
    connection.execute('VACUUM')
    connection.commit()
    connection.close()
    return {'status': 'knowledge_database_vacuum_complete'}
