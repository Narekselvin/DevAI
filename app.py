import json
import subprocess
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request

application_root_directory = Path(__file__).resolve().parent
main_script_path = application_root_directory.joinpath('main.py')

flask_application = Flask(__name__)


@flask_application.route('/')
def serve_dashboard_page():
    return render_template('index.html')


@flask_application.route('/api/run_audit', methods=['POST'])
def execute_audit_and_return_payload():
    if not main_script_path.is_file():
        return jsonify({'error': 'main_script_missing', 'path': str(main_script_path)}), 500
    request_payload = request.get_json(silent=True)
    if request_payload is None:
        request_payload = {}
    subnet_candidate = request_payload.get('subnet')
    audit_command_tokens = [sys.executable, str(main_script_path), 'audit']
    if isinstance(subnet_candidate, str):
        trimmed_subnet_value = subnet_candidate.strip()
        if trimmed_subnet_value:
            audit_command_tokens.extend(['--subnet', trimmed_subnet_value])
    try:
        completed_process = subprocess.run(
            audit_command_tokens,
            cwd=str(application_root_directory),
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=900,
        )
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'audit_timeout'}), 504
    standard_error_text = completed_process.stderr or ''
    standard_output_text = completed_process.stdout or ''
    if completed_process.returncode != 0:
        return (
            jsonify(
                {
                    'error': 'audit_process_failed',
                    'exit_code': completed_process.returncode,
                    'stderr_excerpt': standard_error_text[:4000],
                    'stdout_excerpt': standard_output_text[:4000],
                }
            ),
            500,
        )
    stripped_output = standard_output_text.strip()
    if not stripped_output:
        return jsonify({'error': 'empty_audit_output', 'stderr_excerpt': standard_error_text[:4000]}), 500
    try:
        parsed_audit_document = json.loads(stripped_output)
    except json.JSONDecodeError:
        return (
            jsonify(
                {
                    'error': 'audit_output_not_json',
                    'stdout_excerpt': stripped_output[:8000],
                    'stderr_excerpt': standard_error_text[:4000],
                }
            ),
            500,
        )
    if not isinstance(parsed_audit_document, dict):
        return jsonify({'error': 'audit_payload_not_object'}), 500
    return jsonify(parsed_audit_document)


if __name__ == '__main__':
    flask_application.run(host='127.0.0.1', port=5000, debug=False)
