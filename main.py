import argparse
import json
import sys
from pathlib import Path

from av_analyzer import scan_filesystem_for_integrity_anomalies
from engine import (
    build_query_text_from_antivirus_payload,
    build_query_text_from_log_payload,
    build_query_text_from_scanner_payload,
    generate_structured_remediation_plan,
    merge_query_streams,
    vacuum_knowledge_database,
)
from knowledge_db import ensure_database
from log_analyzer import collect_operating_system_log_insights
from scanner import run_full_system_surface_scan


def build_argument_parser():
    parser_object = argparse.ArgumentParser()
    parser_object.add_argument(
        '--db-path',
        default=str(Path(__file__).resolve().parent.joinpath('sysadmin_knowledge.db')),
        help=argparse.SUPPRESS,
    )
    parser_object.add_argument('--top-matches', type=int, default=5)
    subparsers = parser_object.add_subparsers(dest='command_name')
    audit_parser = subparsers.add_parser('audit')
    audit_parser.add_argument('--include-antivirus', action='store_true')
    audit_parser.add_argument('--subnet', default=None)
    logs_parser = subparsers.add_parser('logs')
    database_init_parser = subparsers.add_parser('database-init')
    database_update_parser = subparsers.add_parser('database-update')
    return parser_object


def execute_full_audit_flow(database_connection, include_antivirus, top_matches_value, subnet_string=None):
    scanner_results_payload = run_full_system_surface_scan(subnet_string)
    antivirus_results_payload = scan_filesystem_for_integrity_anomalies() if include_antivirus else {}
    log_insights_payload = collect_operating_system_log_insights()
    scanner_query_text = build_query_text_from_scanner_payload(scanner_results_payload)
    antivirus_query_text = build_query_text_from_antivirus_payload(antivirus_results_payload)
    log_query_text = build_query_text_from_log_payload(log_insights_payload)
    if include_antivirus is False:
        antivirus_query_text = ''
    merged_query_text = merge_query_streams(scanner_query_text, log_query_text, antivirus_query_text)
    remediation_matches = generate_structured_remediation_plan(database_connection, merged_query_text, top_matches_value)
    output_payload = {
        'analysis_mode': 'full_audit',
        'sources': {
            'scanner_module': 'scanner.py',
            'log_module': 'log_analyzer.py',
            'antivirus_module': 'av_analyzer.py' if include_antivirus else None,
            'knowledge_engine': 'engine.py',
        },
        'scanner_results': scanner_results_payload,
        'log_analysis': log_insights_payload,
        'antivirus_analysis': antivirus_results_payload if include_antivirus else {'skipped': True},
        'remediation_plan': remediation_matches,
        'query_profile': {
            'merged_query_character_length': len(merged_query_text),
            'scanner_query_character_length': len(scanner_query_text),
            'log_query_character_length': len(log_query_text),
            'antivirus_query_character_length': len(antivirus_query_text),
        },
    }
    return output_payload


def execute_targeted_log_analysis_flow(database_connection, top_matches_value):
    log_insights_payload = collect_operating_system_log_insights()
    empty_scanner_placeholder = {'listening_sockets': [], 'weak_permission_findings': [], 'python_package_outdated_report': {'packages': []}, 'configuration_drift_hints': []}
    empty_antivirus_placeholder = {'hash_signature_hits': [], 'yara_signature_hits': [], 'isolated_suspicious_paths': []}
    scanner_query_text = build_query_text_from_scanner_payload(empty_scanner_placeholder)
    antivirus_query_text = build_query_text_from_antivirus_payload(empty_antivirus_placeholder)
    log_query_text = build_query_text_from_log_payload(log_insights_payload)
    merged_query_text = merge_query_streams(scanner_query_text, log_query_text, antivirus_query_text)
    remediation_matches = generate_structured_remediation_plan(database_connection, log_query_text, top_matches_value)
    output_payload = {
        'analysis_mode': 'targeted_log_analysis',
        'sources': {
            'log_module': 'log_analyzer.py',
            'knowledge_engine': 'engine.py',
        },
        'log_analysis': log_insights_payload,
        'remediation_plan': remediation_matches,
        'query_profile': {
            'log_focus_query_character_length': len(log_query_text),
            'merged_query_character_length': len(merged_query_text),
        },
    }
    return output_payload


def main(argv=None):
    parser_object = build_argument_parser()
    parsed_arguments = parser_object.parse_args(argv)
    command_token = parsed_arguments.command_name
    if command_token is None:
        parser_object.print_help()
        return 2
    database_path_value = parsed_arguments.db_path
    top_matches_value = parsed_arguments.top_matches
    if command_token == 'database-init':
        database_connection = ensure_database(database_path_value)
        database_connection.close()
        print(json.dumps({'status': 'database_initialized', 'database_path': database_path_value}, indent=2))
        return 0
    if command_token == 'database-update':
        vacuum_payload = vacuum_knowledge_database(database_path_value)
        print(json.dumps({'status': 'database_maintenance', 'details': vacuum_payload, 'database_path': database_path_value}, indent=2))
        return 0
    database_connection = ensure_database(database_path_value)
    try:
        if command_token == 'audit':
            include_antivirus_flag = parsed_arguments.include_antivirus
            subnet_argument_value = getattr(parsed_arguments, 'subnet', None)
            output_payload = execute_full_audit_flow(
                database_connection,
                include_antivirus_flag,
                top_matches_value,
                subnet_argument_value,
            )
        elif command_token == 'logs':
            output_payload = execute_targeted_log_analysis_flow(database_connection, top_matches_value)
        else:
            parser_object.print_help()
            return 2
    finally:
        database_connection.close()
    print(json.dumps(output_payload, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
