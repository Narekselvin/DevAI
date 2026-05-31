import requests

from knowledge_db import get_connection, insert_alert_log_row


class TelegramNotifier:
    @staticmethod
    def send_alert(message, db_path=None, host_id=None, alert_type='telegram'):
        text_value = str(message or '').strip()
        connection = get_connection(db_path)
        status_value = 'skipped_empty_message'
        ok_result = False
        try:
            if not text_value:
                insert_alert_log_row(connection, host_id, str(alert_type or 'telegram'), '', status_value)
                connection.commit()
                return False
            cursor = connection.cursor()
            cursor.execute("SELECT setting_value FROM system_settings WHERE setting_key = 'telegram_bot_token'")
            token_row = cursor.fetchone()
            cursor.execute("SELECT setting_value FROM system_settings WHERE setting_key = 'telegram_chat_id'")
            chat_row = cursor.fetchone()
            token_value = str((token_row or ('',))[0] or '').strip()
            chat_id_value = str((chat_row or ('',))[0] or '').strip()
            if not token_value or not chat_id_value:
                status_value = 'skipped_credentials'
                insert_alert_log_row(connection, host_id, str(alert_type or 'telegram'), text_value[:8000], status_value)
                connection.commit()
                return False
            url_value = 'https://api.telegram.org/bot' + token_value + '/sendMessage'
            response = requests.post(url_value, json={'chat_id': chat_id_value, 'text': text_value}, timeout=20)
            if response.status_code != 200:
                status_value = 'failed_http_' + str(response.status_code)
                insert_alert_log_row(connection, host_id, str(alert_type or 'telegram'), text_value[:8000], status_value)
                connection.commit()
                return False
            try:
                payload = response.json()
                ok_result = bool(payload.get('ok'))
            except Exception:
                ok_result = True
            status_value = 'delivered' if ok_result else 'failed_telegram_api'
            insert_alert_log_row(connection, host_id, str(alert_type or 'telegram'), text_value[:8000], status_value)
            connection.commit()
            return ok_result
        except Exception:
            status_value = 'exception'
            try:
                insert_alert_log_row(
                    connection,
                    host_id,
                    str(alert_type or 'telegram'),
                    text_value[:8000] if text_value else '',
                    status_value,
                )
                connection.commit()
            except Exception:
                pass
            return False
        finally:
            connection.close()
