"""
Dataset Corrector — looks up known-good corrected commands from the Kali CSV dataset.

Priority order: dataset corrections first, LLM fallback second.
Indexed by (tool, error_class) for O(1) lookup.
"""

from __future__ import annotations

from difflib import SequenceMatcher
from src.capture.error_capture import _extract_tool_name


class DatasetCorrector:
    """Indexes the Kali Linux error dataset and provides corrected commands."""

    def __init__(self):
        # Index: { (tool_lower, error_class) : [ {command, correct_command, error_message, ...}, ... ] }
        self._index = {}
        self._loaded = False

    def load_from_scenarios(self, scenarios: list[dict]):
        """Build the lookup index from parsed dataset scenarios."""
        mismatch_count = 0
        for s in scenarios:
            labeled_tool = s.get('tool', '').strip().lower()
            command = s.get('command', '').strip()
            error_class = s.get('error_class', 'UNKNOWN').strip()
            correct_cmd = s.get('correct_command', '').strip()

            if not command or not correct_cmd or correct_cmd == 'nan':
                continue

            # Derive the actual tool from the command
            derived_tool = _extract_tool_name(command).lower()
            
            if labeled_tool and derived_tool != labeled_tool:
                mismatch_count += 1

            # Use the derived tool for indexing
            key = (derived_tool, error_class)
            self._index.setdefault(key, []).append({
                'command': command,
                'correct_command': correct_cmd,
                'error_message': s.get('error_message', ''),
                'root_cause': s.get('root_cause', ''),
                'remediation_steps': s.get('remediation_steps', ''),
            })

        self._loaded = True
        total = sum(len(v) for v in self._index.values())
        print(f'DatasetCorrector indexed {total} corrections across {len(self._index)} (tool, error_class) keys')
        if mismatch_count > 0:
            print(f'DatasetCorrector ignored {mismatch_count} misleading tool labels in dataset.')

    def lookup_correction(
        self,
        tool: str,
        error_class: str,
        original_command: str,
        stderr: str = '',
    ) -> dict | None:
        """
        Find the best matching corrected command from the dataset.

        Returns a dict with 'correct_command', 'root_cause', 'remediation_steps'
        or None if no match found.
        """
        if not self._loaded:
            return None

        key = (tool.strip().lower(), error_class.strip())
        entries = self._index.get(key, [])

        if not entries:
            return None

        # Score each entry by similarity to the original command
        best_entry = None
        best_score = -1.0

        for entry in entries:
            # Similarity between the original command and the dataset's failed command
            cmd_score = SequenceMatcher(
                None,
                original_command.lower(),
                entry['command'].lower()
            ).ratio()

            # Bonus if stderr contains the dataset's error message keywords
            stderr_bonus = 0.0
            if stderr and entry['error_message']:
                err_words = set(entry['error_message'].lower().split())
                stderr_words = set(stderr.lower().split())
                overlap = err_words & stderr_words
                if err_words:
                    stderr_bonus = len(overlap) / len(err_words) * 0.3

            score = cmd_score + stderr_bonus

            if score > best_score:
                best_score = score
                best_entry = entry

        # Require a minimum relevance score to avoid bad matches
        if best_entry and best_score >= 0.25:
            corrected = best_entry['correct_command']
            # Don't return corrections that are identical to the original
            if corrected.strip().lower() != original_command.strip().lower():
                return {
                    'correct_command': corrected,
                    'root_cause': best_entry.get('root_cause', ''),
                    'remediation_steps': best_entry.get('remediation_steps', ''),
                    'match_score': round(best_score, 3),
                }

        return None

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def entry_count(self) -> int:
        return sum(len(v) for v in self._index.values())
