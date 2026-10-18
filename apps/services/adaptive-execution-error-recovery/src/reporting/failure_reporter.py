"""
Failure Reporter — builds structured failure reports from recovery history.
"""

from src.reporting.audit_logger import query_session


class FailureReporter:

    def build_report(
        self,
        session_id: str,
        final_error_class: str,
        total_attempts: int,
        db_path: str = None,
    ) -> dict:
        """Build a structured failure report including what was tried."""
        events = []
        try:
            events = query_session(session_id, db_path)
        except Exception:
            pass

        strategies_tried = []
        for ev in events:
            strategy = ev.get('strategy_applied')
            if strategy and strategy not in strategies_tried:
                strategies_tried.append(strategy)

        recommendation = self._recommend(final_error_class, strategies_tried)

        return {
            'attempts': total_attempts,
            'final_error_class': final_error_class,
            'strategies_tried': strategies_tried,
            'recommendation': recommendation,
            'audit_trail_count': len(events),
        }

    @staticmethod
    def _recommend(error_class: str, strategies_tried: list) -> str:
        if error_class == 'TOOL_NOT_INSTALLED':
            if 'INSTALL_TOOL' in strategies_tried:
                return 'Auto-install failed. Manually install the tool or use a pre-built image.'
            return 'Install the required tool in the container image.'
        if error_class == 'PERMISSION_DENIED':
            return 'Check container privileges or file permissions.'
        if error_class == 'NETWORK_UNREACHABLE':
            return 'Verify target host is reachable and network settings are correct.'
        if error_class == 'WRONG_SYNTAX':
            return 'Review command flags against the tool\'s help output.'
        if error_class == 'RESOURCE_EXHAUSTION':
            return 'Increase container memory/CPU limits or reduce scan scope.'
        if error_class == 'AUTH_FAILURE':
            return 'Check credentials and authentication method.'
        if error_class == 'TIMEOUT':
            if 'ADJUST_TIMEOUT' in strategies_tried:
                return 'Timeout persists after adjustment. Target may be unresponsive.'
            return 'Increase timeout or reduce scan scope.'
        if error_class == 'VERSION_MISMATCH':
            return 'Update or downgrade the tool to a compatible version.'
        return 'Manual intervention required — error could not be automatically resolved.'
