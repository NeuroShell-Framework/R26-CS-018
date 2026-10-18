import React from 'react';

export default function PipelineVisualizer({ currentStage, isError, errorStage }) {
  const stages = [
    { id: 'intent', label: 'Structured Intent', icon: '📝' },
    { id: 'interpreter', label: 'Intent Interpreter', icon: '🔍' },
    { id: 'rag', label: 'RAG Retrieval', icon: '📚' },
    { id: 'llm', label: 'Gemma / Ollama', icon: '🧠' },
    { id: 'safety', label: 'Safety Filter', icon: '🛡️' },
    { id: 'validator', label: 'Command Validator', icon: '⚙️' },
    { id: 'output', label: 'PlannerOutput', icon: '📄' },
    { id: 'c3', label: 'Component 03', icon: '⚡', isBoundary: true }
  ];

  const getStageStatus = (stageId, index) => {
    if (isError && errorStage === stageId) return 'error';
    if (!currentStage) return 'idle';
    
    const currentIndex = stages.findIndex(s => s.id === currentStage);
    if (index < currentIndex) return 'completed';
    if (index === currentIndex) return 'active';
    return 'idle';
  };

  return (
    <div className="glass-panel pipeline-panel">
      <div className="section-title">
        🔄 Pipeline Stage Visualization & Component Boundary
      </div>
      
      <div className="pipeline-stepper">
        {stages.map((stage, idx) => {
          const status = getStageStatus(stage.id, idx);
          return (
            <React.Fragment key={stage.id}>
              <div className={`pipeline-step ${status} ${stage.isBoundary ? 'boundary' : ''}`}>
                <div className="step-circle">
                  {status === 'completed' ? '✓' : stage.icon}
                </div>
                <div className="step-label">
                  {stage.label}
                  {stage.isBoundary && (
                    <div style={{ fontSize: '9px', color: 'var(--status-amber)', fontStyle: 'italic', marginTop: '2px' }}>
                      (Execution Boundary)
                    </div>
                  )}
                </div>
              </div>

              {idx < stages.length - 1 && (
                <div className="step-arrow">➔</div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
