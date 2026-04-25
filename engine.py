import re

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from knowledge_db import get_connection


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
                    'cpu',
                    str(device.get('cpu_utilization', '')),
                    'ram',
                    str(device.get('ram_usage', '')),
                    'disk',
                    str(device.get('disk_usage', '')),
                    'temp',
                    str(device.get('temperature_c', '')),
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


def _load_hardware_playbooks(connection, target_language):
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
    return documents, metadata


def _get_issue_key(device):
    if str(device.get('status')) == 'offline':
        return 'OFFLINE'
    if int(device.get('temperature_c', 0)) >= 80:
        return 'HIGH_TEMP'
    if int(device.get('disk_usage', 0)) > 95:
        return 'DISK_FULL'
    if int(device.get('cpu_utilization', 0)) > 85:
        return 'HIGH_CPU'
    return 'NORMAL'


def generate_snmp_device_recommendations(connection, snmp_metrics, target_language='en', maximum_matches=5):
    language = target_language if target_language in ('en', 'ru', 'hy') else 'en'
    docs, metadata = _load_hardware_playbooks(connection, language)
    if not docs:
        return []
    vectorizer = TfidfVectorizer(max_features=4096, ngram_range=(1, 2))
    matrix = vectorizer.fit_transform(docs)
    recommendations = []
    for device in snmp_metrics or []:
        issue_key = _get_issue_key(device)
        if issue_key == 'NORMAL':
            continue
        if issue_key == 'HIGH_TEMP' and int(device.get('cpu_utilization', 0)) >= 95:
            custom_text = _localize(
                language,
                f"{device.get('hostname', 'Device')} temp is critical. Needs physical cleaning or thermal paste replacement.",
                f"У {device.get('hostname', 'Device')} критическая температура. Требуется физическая очистка или замена термопасты.",
                f"{device.get('hostname', 'Device')} սարքի ջերմաստիճանը կրիտիկական է։ Պահանջվում է ֆիզիկական մաքրում կամ թերմոպաստայի փոխարինում։",
            )
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
        recommendations.append(
            {
                'device': device.get('hostname'),
                'ip': device.get('ip'),
                'issue_key': issue_key,
                'title': best_metadata['title'],
                'resolution_steps': str(device.get('hostname')) + ': ' + best_metadata['remediation'],
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
        if int(device.get('cpu_utilization', 0)) > 85:
            score_value -= 2
        if int(device.get('temperature_c', 0)) >= 80:
            score_value -= 5
        if int(device.get('disk_usage', 0)) > 95:
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
        if int(device.get('cpu_utilization', 0)) > 85:
            high_cpu_count += 1
        if int(device.get('temperature_c', 0)) >= 80:
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


def _fetch_metrics_history(connection, host_id, limit_value=5):
    cursor = connection.cursor()
    cursor.execute(
        'SELECT status, cpu_utilization, ram_usage, disk_usage, temperature_c, mock_data, polled_at '
        'FROM metrics_history WHERE host_id = ? ORDER BY datetime(polled_at) DESC, id DESC LIMIT ?',
        (int(host_id), int(limit_value)),
    )
    rows = cursor.fetchall()
    history = []
    for status, cpu, ram, disk, temp, mock_data, polled_at in rows:
        history.append(
            {
                'status': str(status),
                'cpu_utilization': int(cpu),
                'ram_usage': int(ram),
                'disk_usage': int(disk),
                'temperature_c': int(temp),
                'mock_data': bool(int(mock_data)),
                'polled_at': str(polled_at),
            }
        )
    return history


def _detect_trend_issue(history_rows):
    if not history_rows:
        return 'NORMAL', {}
    offline_count = sum(1 for r in history_rows if str(r.get('status')) == 'offline')
    cpu_spikes = sum(1 for r in history_rows if int(r.get('cpu_utilization', 0)) > 90)
    temp_spikes = sum(1 for r in history_rows if int(r.get('temperature_c', 0)) >= 80)
    disk_spikes = sum(1 for r in history_rows if int(r.get('disk_usage', 0)) > 95)
    trend = {
        'samples': len(history_rows),
        'offline_count': offline_count,
        'cpu_spikes': cpu_spikes,
        'temp_spikes': temp_spikes,
        'disk_spikes': disk_spikes,
    }
    if offline_count >= 2:
        return 'OFFLINE', trend
    if temp_spikes >= 2:
        return 'HIGH_TEMP', trend
    if disk_spikes >= 2:
        return 'DISK_FULL', trend
    if cpu_spikes >= 3:
        return 'HIGH_CPU', trend
    return 'NORMAL', trend


def _format_trend_text(language, hostname, issue_key, trend):
    samples = int(trend.get('samples', 0))
    if issue_key == 'HIGH_CPU':
        return _localize(
            language,
            f"{hostname} shows recurring high CPU (>90%) in {trend.get('cpu_spikes', 0)}/{samples} recent polls. This is a trend, not a one-off spike.",
            f"На {hostname} наблюдается повторяющаяся высокая загрузка CPU (>90%) в {trend.get('cpu_spikes', 0)}/{samples} последних опросов. Это тренд, а не разовый пик.",
            f"{hostname} սարքի մոտ նկատվում է կրկնվող բարձր CPU (>90%) {trend.get('cpu_spikes', 0)}/{samples} վերջին հարցումներում։ Սա միտում է, ոչ թե մեկանգամյա պիկ։",
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
            f"{hostname} հաճախակի անհասանելի է {trend.get('offline_count', 0)}/{samples} վերջին հարցումներում։ Ստուգեք սնուցումը և ցանցի կայունությունը։",
            f"У {hostname} устройство часто недоступно в {trend.get('offline_count', 0)}/{samples} последних опросов. Проверьте питание/стабильность сети.",
        )
    return ''


def generate_ai_decisions_from_metrics_history(connection, target_language='en', maximum_results=25):
    language = target_language if target_language in ('en', 'ru', 'hy') else 'en'
    cursor = connection.cursor()
    cursor.execute('SELECT id, hostname, ip_address, device_type FROM hosts ORDER BY id')
    hosts = cursor.fetchall()
    docs, metadata = _load_hardware_playbooks(connection, language)
    vectorizer = TfidfVectorizer(max_features=4096, ngram_range=(1, 2))
    matrix = vectorizer.fit_transform(docs) if docs else None
    decisions = []
    for host_id, hostname, ip_address, device_type in hosts:
        history = _fetch_metrics_history(connection, host_id, 5)
        issue_key, trend = _detect_trend_issue(history)
        if issue_key == 'NORMAL':
            continue
        trend_text = _format_trend_text(language, str(hostname), issue_key, trend)
        best_entry = None
        score_value = 0.0
        if matrix is not None:
            query_text = normalize_free_text_for_matching(str(issue_key) + ' ' + build_query_text_from_snmp_metrics(history))
            query_vector = vectorizer.transform([query_text])
            similarity_scores = cosine_similarity(query_vector, matrix).flatten()
            best_index = int(np.argmax(similarity_scores)) if len(similarity_scores) else 0
            score_value = float(similarity_scores[best_index]) if len(similarity_scores) else 0.0
            best_entry = metadata[best_index] if metadata else None
        if not best_entry:
            best_entry = {'title': issue_key, 'remediation': '', 'remediation_script': ''}
        script_block = _select_safe_script_snippet(str(device_type), issue_key, best_entry.get('remediation_script', ''))
        decisions.append(
            {
                'host_id': int(host_id),
                'hostname': str(hostname),
                'ip_address': str(ip_address),
                'device_type': str(device_type),
                'issue_key': str(issue_key),
                'title': str(best_entry.get('title') or issue_key),
                'trend_analysis': trend_text,
                'resolution_text': str(best_entry.get('remediation') or ''),
                'script': script_block.get('script'),
                'script_language': script_block.get('language'),
                'similarity_score': score_value,
            }
        )
    decisions.sort(key=lambda item: item.get('similarity_score', 0.0), reverse=True)
    return decisions[: int(maximum_results)]


def _select_safe_script_snippet(device_type, issue_key, fallback_script):
    normalized_type = str(device_type or '').strip().lower()
    is_windows = normalized_type == 'server' and 'windows' in normalized_type
    if issue_key == 'HIGH_CPU':
        if normalized_type in ('server', 'vm'):
            return {'language': 'powershell', 'script': 'Restart-Service -Name W3SVC -ErrorAction SilentlyContinue'}
        return {'language': 'bash', 'script': 'systemctl restart nginx || true'}
    if issue_key == 'DISK_FULL':
        if normalized_type in ('server', 'vm'):
            return {'language': 'bash', 'script': 'rm -rf /tmp/*'}
        return {'language': 'bash', 'script': 'du -h -d 1 /var/log | sort -h | tail -n 20'}
    if issue_key == 'HIGH_TEMP':
        return {'language': 'bash', 'script': 'echo \"Check fans/airflow; schedule hardware maintenance\"'}
    if issue_key == 'OFFLINE':
        return {'language': 'bash', 'script': 'ping -c 2 127.0.0.1'}
    script_value = str(fallback_script or '').strip()
    return {'language': 'bash', 'script': script_value} if script_value else {'language': 'bash', 'script': 'echo \"No script available\"'}


def vacuum_knowledge_database(db_path=None):
    connection = get_connection(db_path)
    connection.execute('VACUUM')
    connection.commit()
    connection.close()
    return {'status': 'knowledge_database_vacuum_complete'}
