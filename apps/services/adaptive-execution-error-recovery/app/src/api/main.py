import time
import os
import traceback
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from src.schemas.models import (
    PlannerOutput, ExecutionResult, RecoveryLogEntry, RecoveryPlan,
    CorrectionEntry
)
from src.execution.command_runner import CommandRunner
from src.execution.silent_failure_detector import is_silent_failure
from src.capture.error_capture import build_error_context
from src.classification.regex_classifier import RegexClassifier
from src.classification.embedding_classifier import EmbeddingClassifier
from src.classification.llm_causal_reasoner import call_llm_reasoner
from src.mutation.mutation_engine import MutationEngine
from src.mutation.dataset_corrector import DatasetCorrector
from src.safety.safety_gate import validate as safety_validate
from src.retry.retry_orchestrator import RetryOrchestrator
from src.reporting.audit_logger import init_db, log_event, query_session
from src.reporting.failure_reporter import FailureReporter
from src.session.session_context import SessionContext

load_dotenv()

DB_PATH = os.getenv('AUDIT_DB_PATH', './data/audit.db')

runner     = None
regex_clf  = None
embed_clf  = None
mutator    = None
retry_orch = None
session    = None
reporter   = None
ds_corrector = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global runner, regex_clf, embed_clf, mutator, retry_orch, session, reporter, ds_corrector
    print("Initialising AEERE modules...")
    init_db(DB_PATH)
    runner     = CommandRunner()
    regex_clf  = RegexClassifier()

    # ── Load Kali dataset for both classifier enrichment and corrections ──
    ds_corrector = DatasetCorrector()
    try:
        from kali_data.dataset_loader import load_dataset
        scenarios = load_dataset('kali_data/kali_linux_error.csv')
        regex_clf.enrich_from_dataset(scenarios)
        ds_corrector.load_from_scenarios(scenarios)
        print(f'Dataset loaded: {len(scenarios)} scenarios')
    except Exception as e:
        print(f'Dataset load skipped: {e}')

    try:
        embed_clf = EmbeddingClassifier()
    except Exception as e:
        embed_clf = None
        print(f'Embedding classifier unavailable: {e}')

    mutator    = MutationEngine(dataset_corrector=ds_corrector)
    retry_orch = RetryOrchestrator()
    session    = SessionContext()
    reporter   = FailureReporter()
    print("All modules ready.")
    yield
    print("AEERE shutting down.")


app = FastAPI(
    title='NeuroShell AEERE',
    version='1.0.0',
    description='Adaptive Execution and Error Recovery Engine — Component 03',
    lifespan=lifespan,
    responses={
        422: {"description": "Invalid Request Format"}
    }
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*']
)


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    print(f"GLOBAL ERROR: {exc}")
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content=ExecutionResult(
            session_id='error',
            status='failed',
            command_executed='',
            stdout='',
            stderr=f'Internal error: {exc}',
            exit_code=1,
            recovery_log=[],
            correction_history=[],
            failure_report={
                'attempts': 0,
                'final_error_class': 'INTERNAL_ERROR',
                'recommendation': 'Server encountered an unexpected error'
            },
            tool_substituted=False,
            latency_ms=0
        ).model_dump()
    )


@app.get('/health')
def health():
    docker_ok = runner.check_docker_available() if runner else False
    redis_ok  = session.available if session else False
    ds_ok     = ds_corrector.is_loaded if ds_corrector else False
    return {
        'status':  'healthy',
        'docker':  docker_ok,
        'redis':   redis_ok,
        'dataset_corrections': ds_ok,
        'dataset_entries': ds_corrector.entry_count if ds_corrector else 0,
        'model':   os.getenv('OLLAMA_MODEL', 'qwen2.5-coder:latest'),
        'version': '1.0.0'
    }


def _build_default_plan(error_class: str, confidence: float,
                        command: str) -> RecoveryPlan:
    strategy_map = {
        'TOOL_NOT_INSTALLED':  'INSTALL_TOOL',
        'PERMISSION_DENIED':   'ADD_SUDO',
        'NETWORK_UNREACHABLE': 'ADJUST_PARAMETERS',
        'WRONG_SYNTAX':        'FIX_SYNTAX',
        'RESOURCE_EXHAUSTION': 'ADJUST_PARAMETERS',
        'AUTH_FAILURE':        'FIX_AUTH',
        'TIMEOUT':             'ADJUST_TIMEOUT',
        'VERSION_MISMATCH':    'VERSION_DOWNGRADE',
        'UNKNOWN':             'ESCALATE',
    }
    return RecoveryPlan(
        error_class=error_class,
        root_cause='Classified by pattern matching',
        strategy=strategy_map.get(error_class, 'ESCALATE'),
        corrected_command=command,
        confidence=confidence,
        reasoning='Regex or embedding classification'
    )


@app.post('/execute', response_model=ExecutionResult)
async def execute(payload: PlannerOutput):
    start            = time.time()
    prior_strategies = session.get_prior_strategies(payload.session_id)
    current_command  = payload.command
    recovery_log     = []
    correction_history = []
    attempt          = 0
    tool_substituted = False
    status           = 'failed'
    final_raw        = None
    error_class      = 'UNKNOWN'
    confidence       = 0.0
    deadline_secs    = float(os.getenv('AEERE_DEADLINE_SECONDS', '240'))

    while True:

        # ── Hard wall-clock deadline: always return a proper ExecutionResult
        #    before the upstream chain client (~300s) can time out, so the
        #    recovery loop (not a transport error) is what surfaces.
        if (time.time() - start) > deadline_secs:
            if error_class in (None, '', 'UNKNOWN'):
                error_class = 'TIMEOUT'
                confidence  = 1.0
            status = 'failed'
            break

        attempt += 1
        try:
            # ── STAGE 0: Safety check original command ────────────
            if attempt == 1:
                initial_safety = safety_validate(
                    current_command,
                    RecoveryPlan(
                        error_class='UNKNOWN',
                        root_cause='Initial command check',
                        strategy='ESCALATE',
                        corrected_command=current_command,
                        confidence=1.0,
                        reasoning='Pre-execution safety check'
                    )
                )
                if not initial_safety.approved:
                    return ExecutionResult(
                        session_id=payload.session_id,
                        status='failed',
                        command_executed=current_command,
                        stdout='',
                        stderr='Blocked by safety gate: ' + initial_safety.reason,
                        exit_code=1,
                        recovery_log=[],
                        correction_history=[],
                        failure_report={
                            'attempts': 0,
                            'final_error_class': 'SAFETY_BLOCKED',
                            'recommendation': initial_safety.reason
                        },
                        tool_substituted=False,
                        latency_ms=0
                    )

            # ── STAGE 1: Execute ──────────────────────────────────
            raw       = runner.execute(current_command)
            final_raw = raw

            silent = is_silent_failure(
                payload.tool, raw.stdout, raw.exit_code, current_command,
                stderr=raw.stderr
            )

            # ── SUCCESS CHECK ─────────────────────────────────────
            if raw.exit_code == 0 and not silent:
                status = 'success' if attempt == 1 else 'recovered'
                break

            # ── STAGE 2: Classify error ───────────────────────────
            clf_start  = time.time()
            clf_method = 'regex'

            if raw.timed_out:
                # Deterministic classification: container was stopped at the
                # exec timeout, there is nothing meaningful to match on stderr.
                error_class = 'TIMEOUT'
                confidence  = 1.0
            else:
                error_class, confidence = regex_clf.classify(raw.stderr, raw.exit_code)

                if error_class is None and embed_clf is not None:
                    clf_method  = 'embedding'
                    error_class, confidence = embed_clf.classify(raw.stderr)

            ctx = build_error_context(
                raw, payload.session_id, payload.intent_ref,
                attempt, prior_strategies, silent
            )

            recovery_plan = None

            if not raw.timed_out and error_class is None:
                clf_method    = 'llm'
                recovery_plan = call_llm_reasoner(ctx)
                if recovery_plan:
                    error_class = recovery_plan.error_class
                    confidence  = recovery_plan.confidence

            if error_class is None:
                error_class = 'UNKNOWN'
                confidence  = 0.0

            clf_latency = (time.time() - clf_start) * 1000

            # ── STAGE 3: Check retry budget ───────────────────────
            if not retry_orch.should_retry(error_class, attempt):
                log_event({
                    'session_id': payload.session_id,
                    'attempt_number': attempt,
                    'original_command': payload.command,
                    'stderr': raw.stderr,
                    'exit_code': raw.exit_code,
                    'error_class': error_class,
                    'classification_method': clf_method,
                    'classification_latency_ms': clf_latency,
                    'strategy_applied': 'BUDGET_EXHAUSTED',
                    'corrected_command': '',
                    'safety_approved': False,
                    'danger_words': [],
                    'confidence': confidence,
                    'llm_reasoning': '',
                    'outcome': 'budget_exhausted',
                    'total_latency_ms': (time.time() - start) * 1000
                }, DB_PATH)
                break

            # ── STAGE 4: Build recovery plan ──────────────────────
            if recovery_plan is None:
                recovery_plan = _build_default_plan(
                    error_class, confidence, current_command
                )

            # ── STAGE 5: Apply mutation (dataset → LLM → rule-based) ─
            corrected, correction_source = mutator.apply_mutation(recovery_plan, ctx)

            if corrected is None:
                log_event({
                    'session_id': payload.session_id,
                    'attempt_number': attempt,
                    'original_command': payload.command,
                    'stderr': raw.stderr,
                    'exit_code': raw.exit_code,
                    'error_class': error_class,
                    'classification_method': clf_method,
                    'classification_latency_ms': clf_latency,
                    'strategy_applied': recovery_plan.strategy,
                    'corrected_command': '',
                    'safety_approved': False,
                    'danger_words': [],
                    'confidence': confidence,
                    'llm_reasoning': recovery_plan.reasoning,
                    'outcome': 'no_mutation',
                    'total_latency_ms': (time.time() - start) * 1000
                }, DB_PATH)
                break

            recovery_plan.corrected_command = corrected

            # ── Display corrected command ─────────────────────────
            print(f'\n{"="*60}')
            print(f'[AEERE] CORRECTED COMMAND (attempt {attempt})')
            print(f'  Original : {current_command}')
            print(f'  Corrected: {corrected}')
            print(f'  Source   : {correction_source}')
            print(f'  Strategy : {recovery_plan.strategy}')
            print(f'  Error    : {error_class} (conf={confidence:.2f})')
            print(f'{"="*60}\n')

            # ── SAFETY GATE ───────────────────────────────────────
            safety   = safety_validate(corrected, recovery_plan)
            approved = safety.approved

            # ── AUDIT LOG ─────────────────────────────────────────
            log_event({
                'session_id': payload.session_id,
                'attempt_number': attempt,
                'original_command': payload.command,
                'stderr': raw.stderr,
                'exit_code': raw.exit_code,
                'error_class': error_class,
                'classification_method': clf_method,
                'classification_latency_ms': clf_latency,
                'strategy_applied': recovery_plan.strategy,
                'corrected_command': corrected,
                'safety_approved': approved,
                'danger_words': safety.danger_words_found,
                'confidence': confidence,
                'llm_reasoning': recovery_plan.reasoning,
                'outcome': 'approved' if approved else 'blocked',
                'total_latency_ms': (time.time() - start) * 1000
            }, DB_PATH)

            # ── Build recovery log entry with corrected command ───
            recovery_log.append(RecoveryLogEntry(
                attempt          = attempt,
                error_class      = error_class,
                strategy         = recovery_plan.strategy,
                clf_method       = clf_method,
                confidence       = confidence,
                original_command = current_command,
                corrected_command = corrected,
            ))

            # ── Build correction history entry ────────────────────
            correction_history.append(CorrectionEntry(
                attempt           = attempt,
                original_command  = current_command,
                corrected_command = corrected,
                error_class       = error_class,
                strategy          = recovery_plan.strategy,
                approved          = approved,
                correction_source = correction_source,
            ))

            if not approved:
                break

            prior_strategies.append(recovery_plan.strategy)
            current_command = corrected

            if recovery_plan.strategy == 'TOOL_SUBSTITUTION':
                tool_substituted = True

            await retry_orch.wait(error_class, attempt)

        except Exception as e:
            print(f"Recovery loop error at attempt {attempt}: {e}")
            traceback.print_exc()
            break

    session.update(
        payload.session_id,
        current_command,
        payload.tool,
        '',
        status
    )

    total_ms = int((time.time() - start) * 1000)

    # ── Success-path audit logging ────────────────────────────
    if status in ('success', 'recovered'):
        try:
            log_event({
                'session_id': payload.session_id,
                'attempt_number': attempt,
                'original_command': payload.command,
                'stderr': final_raw.stderr[:500] if final_raw else '',
                'exit_code': final_raw.exit_code if final_raw else 0,
                'error_class': error_class if status == 'recovered' else None,
                'classification_method': None,
                'classification_latency_ms': None,
                'strategy_applied': None,
                'corrected_command': current_command,
                'safety_approved': True,
                'danger_words': [],
                'confidence': confidence,
                'llm_reasoning': None,
                'outcome': status,
                'total_latency_ms': total_ms
            }, DB_PATH)
        except Exception as e:
            print(f'Success audit log failed: {e}')

    failure_report = None
    if status == 'failed':
        if reporter:
            failure_report = reporter.build_report(
                payload.session_id, error_class, attempt, DB_PATH
            )
        else:
            failure_report = {
                'attempts':          attempt,
                'final_error_class': error_class,
                'recommendation':    'Manual intervention required'
            }

    return ExecutionResult(
        session_id       = payload.session_id,
        status           = status,
        command_executed = current_command,
        stdout           = final_raw.stdout if final_raw else '',
        stderr           = final_raw.stderr if final_raw else '',
        exit_code        = final_raw.exit_code if final_raw else 1,
        recovery_log     = recovery_log,
        correction_history = correction_history,
        failure_report   = failure_report,
        tool_substituted = tool_substituted,
        latency_ms       = total_ms
    )


@app.get('/sessions/{session_id}')
def get_session(session_id: str):
    """Query audit trail for a session."""
    events = query_session(session_id, DB_PATH)
    return {'session_id': session_id, 'events': events, 'count': len(events)}