import asyncio
import json


class RetryOrchestrator:

    def __init__(self, taxonomy_path='taxonomy/error_taxonomy.json'):
        with open(taxonomy_path) as f:
            taxonomy = json.load(f)
        self.taxonomy = taxonomy['error_classes']

    def get_budget(self, error_class: str) -> dict:
        if error_class in self.taxonomy:
            return self.taxonomy[error_class]
        # Default budget for UNKNOWN class
        return {'max_retries': 1, 'backoff': 'fixed', 'backoff_seconds': 0}

    def should_retry(self, error_class: str, attempt_number: int) -> bool:
        budget = self.get_budget(error_class)
        return attempt_number <= budget['max_retries']

    def _compute_wait_seconds(self, error_class: str, attempt_number: int) -> float:
        budget = self.get_budget(error_class)
        if budget['backoff'] == 'exponential':
            return budget['backoff_seconds'] * (2 ** (attempt_number - 1))
        return budget['backoff_seconds']

    async def wait(self, error_class: str, attempt_number: int):
        seconds = self._compute_wait_seconds(error_class, attempt_number)
        if seconds > 0:
            await asyncio.sleep(seconds)

    def get_max_retries(self, error_class: str) -> int:
        return self.get_budget(error_class)['max_retries']
