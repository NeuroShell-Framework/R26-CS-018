import React from 'react';

export default function SafetyAlert({ errorData, status }) {
  if (!errorData) return null;

  const isValidatorError = status === 422 || errorData?.stage === 'command_validator';
  const isRejectedIntent = errorData?.error === 'INTENT_REJECTED' || errorData?.stage === 'intent_filter';

  let title = '🛡️ REQUEST BLOCKED BY SAFETY FILTER';
  if (isValidatorError) {
    title = '⚙️ COMMAND VALIDATION FAILED (HTTP 422)';
  } else if (isRejectedIntent) {
    title = '⛔ INTENT REJECTED BY INTENT FILTER (HTTP 400)';
  }

  let detailText = '';
  if (typeof errorData.detail === 'string') {
    detailText = errorData.detail;
  } else if (errorData.detail?.detail) {
    detailText = errorData.detail.detail;
  } else if (errorData.detail?.error) {
    detailText = `${errorData.detail.error}: ${errorData.detail.detail || ''}`;
  } else {
    detailText = JSON.stringify(errorData.detail || errorData);
  }

  return (
    <div className={`glass-panel alert-box blocked`}>
      <div className="alert-title">
        {title}
      </div>
      <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
        {isValidatorError
          ? 'The synthesized command failed structural validation checks (empty command, wrong binary prefix, or missing mandatory flags).'
          : isRejectedIntent
          ? 'The requested intent was classified as REJECTED by C1 and was intercepted before RAG or LLM resource consumption.'
          : 'The request was intercepted before plan generation due to safety guardrails (e.g. RFC-1918 private IPv4 scope restriction or dangerous command patterns).'}
      </div>
      <div className="alert-detail">
        {detailText}
      </div>
    </div>
  );
}
