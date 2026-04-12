import re

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from knowledge_db import get_connection


def load_remediation_documents(connection):
    cursor = connection.cursor()
    cursor.execute(
        'SELECT remediation_id, title, mapped_symptoms, resolution_steps FROM remediations ORDER BY remediation_id'
    )
    rows = cursor.fetchall()
    combined_documents = []
    metadata_rows = []
    for remediation_id, title_text, mapped_symptoms_text, resolution_steps_text in rows:
        merged_text = ' '.join(
            fragment for fragment in [title_text, mapped_symptoms_text, resolution_steps_text] if fragment
        )
        combined_documents.append(merged_text)
        metadata_rows.append(
            {
                'remediation_id': remediation_id,
                'title': title_text,
                'resolution_steps': resolution_steps_text,
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


def generate_structured_remediation_plan(connection, primary_query_text, maximum_matches):
    combined_documents, metadata_rows = load_remediation_documents(connection)
    return compute_tfidf_similarity_ranking(primary_query_text, combined_documents, metadata_rows, maximum_matches)


def merge_query_streams(scanner_text, log_text, antivirus_text):
    merged_segments = [scanner_text, log_text, antivirus_text]
    merged_segments = [segment for segment in merged_segments if segment]
    return normalize_free_text_for_matching(' '.join(merged_segments))


def vacuum_knowledge_database(db_path=None):
    connection = get_connection(db_path)
    connection.execute('VACUUM')
    connection.commit()
    connection.close()
    return {'status': 'knowledge_database_vacuum_complete'}
