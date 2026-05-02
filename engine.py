import re
from datetime import datetime

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


def _fetch_metrics_history(connection, host_id, limit_value=5, oldest_first=False):
    cursor = connection.cursor()
    if oldest_first:
        cursor.execute(
            'SELECT status, cpu_utilization, ram_usage, disk_usage, temperature_c, mock_data, polled_at '
            'FROM metrics_history WHERE host_id = ? ORDER BY datetime(polled_at) ASC, id ASC LIMIT ?',
            (int(host_id), int(limit_value)),
        )
    else:
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
        points.append((moment, float(row.get(metric_key, 0))))
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


def _combine_predictive_signals(language_value, hostname_value, history_chronological, device_kind):
    prioritized_strings = []
    metric_definitions = [('cpu_utilization', 'CPU', 95)]
    if str(device_kind) != 'VM':
        metric_definitions.append(('temperature_c', 'Thermal edge', 80))
    metric_definitions.extend([('ram_usage', 'RAM', 92), ('disk_usage', 'Disk', 95)])
    for metric_key_loop, readable_label, cutoff_value in metric_definitions:
        horizon_payload = _forecast_linear_horizon(history_chronological, metric_key_loop, cutoff_value)
        if not horizon_payload:
            continue
        slope_part, horizon_part = horizon_payload
        prioritized_strings.append(_format_predictive_text(language_value, hostname_value, readable_label, slope_part, horizon_part))
    if not prioritized_strings:
        return ''
    return prioritized_strings[0]


def _detect_trend_issue(history_rows, canonical_device_kind='Server'):
    if not history_rows:
        return 'NORMAL', {}
    offline_count = sum(1 for r in history_rows if str(r.get('status')) == 'offline')
    cpu_spikes = sum(1 for r in history_rows if int(r.get('cpu_utilization', 0)) > 90)
    temp_spikes = sum(1 for r in history_rows if int(r.get('temperature_c', 0)) >= 80)
    if canonical_device_kind == 'VM':
        temp_spikes = 0
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
            f"У {hostname} часто наблюдается недоступность в {trend.get('offline_count', 0)}/{samples} последних опросов. Проверьте питание и стабильность сети.",
            f"{hostname}-ը անհամապատասխան հասանելի է եղել {trend.get('offline_count', 0)}/{samples} վերջին հարցումներում։ Ստուգեք սնուցումը և ցանցը։",
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
    for host_id_value, hostname_value, ip_address_value, device_kind in hosts:
        history_descending = _fetch_metrics_history(connection, host_id_value, 40, oldest_first=False)
        history_ascending = _fetch_metrics_history(connection, host_id_value, 120, oldest_first=True)
        issue_key_primary, trend_struct = _detect_trend_issue(history_descending, str(device_kind))
        predictive_narrative = _combine_predictive_signals(language, str(hostname_value), history_ascending, str(device_kind))
        dependency_story, dependency_shell = _collect_dependency_pressure_hint(
            connection, language, int(host_id_value), str(hostname_value)
        )
        if issue_key_primary == 'NORMAL' and not predictive_narrative and not dependency_story:
            continue
        trend_fragment = ''
        if issue_key_primary != 'NORMAL':
            trend_fragment = _format_trend_text(language, str(hostname_value), issue_key_primary, trend_struct)
        merged_narrative = ' '.join([trend_fragment, predictive_narrative, dependency_story]).strip()
        tfidf_issue_token = issue_key_primary
        if issue_key_primary == 'NORMAL' and predictive_narrative:
            tfidf_issue_token = 'HIGH_CPU'
        if issue_key_primary == 'NORMAL' and dependency_story and not predictive_narrative:
            tfidf_issue_token = 'HIGH_CPU'
        query_payload = history_descending[:10] if history_descending else history_ascending[-10:]
        query_text = normalize_free_text_for_matching(
            str(tfidf_issue_token) + ' ' + build_query_text_from_snmp_metrics(query_payload) + ' ' + merged_narrative
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
        if predictive_narrative:
            score_value = max(score_value, 0.35)
        if dependency_story:
            score_value = max(score_value, 0.42)
        script_block = _select_safe_script_snippet(str(device_kind), tfidf_issue_token, best_entry.get('remediation_script', ''))
        if dependency_shell:
            base_script = str(script_block.get('script') or '').strip()
            stack_script = base_script + '\n\n' + dependency_shell if base_script else dependency_shell
            script_block['script'] = stack_script.strip()
        decisions.append(
            {
                'host_id': int(host_id_value),
                'hostname': str(hostname_value),
                'ip_address': str(ip_address_value),
                'device_type': str(device_kind),
                'issue_key': str(tfidf_issue_token),
                'title': str(best_entry.get('title') or tfidf_issue_token),
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
    if issue_key == 'HIGH_CPU':
        if normalized_type in ('server', 'vm'):
            return {
                'language': 'powershell',
                'script': 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 Name,CPU,Id',
            }
        return {'language': 'bash', 'script': 'systemctl restart nginx || true'}
    if issue_key == 'DISK_FULL':
        if normalized_type in ('server', 'vm'):
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
