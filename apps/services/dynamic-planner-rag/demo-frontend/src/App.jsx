import React, { useState } from 'react';
import Header from './components/Header';
import StatusPanel from './components/StatusPanel';
import Presets from './components/Presets';
import PlannerForm from './components/PlannerForm';
import PipelineVisualizer from './components/PipelineVisualizer';
import PlannerOutput from './components/PlannerOutput';
import SafetyAlert from './components/SafetyAlert';
import MetricsPanel from './components/MetricsPanel';
import ApiKeyModal from './components/ApiKeyModal';

import { generatePlan } from './services/api';

export default function App() {
  const [apiKey, setApiKey] = useState(() => {
    return localStorage.getItem('c2_api_key') || 'neuroshell-secret-key';
  });

  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);

  const [formData, setFormData] = useState({
    intent: 'NETWORK_SCAN',
    targetType: 'IP',
    targetValue: '192.168.1.1',
    primaryTool: 'nmap',
    ports: '80, 443',
    modifiers: ['stealth'],
    confidence: 0.95,
    sessionId: 'demo-sess-001'
  });

  const [loading, setLoading] = useState(false);
  const [currentStage, setCurrentStage] = useState('intent');
  const [outputData, setOutputData] = useState(null);
  const [errorData, setErrorData] = useState(null);
  const [errorStatus, setErrorStatus] = useState(null);

  const handleSaveApiKey = (newKey) => {
    setApiKey(newKey);
    localStorage.setItem('c2_api_key', newKey);
  };

  const handleSelectPreset = (preset) => {
    setFormData(prev => ({
      ...prev,
      intent: preset.intent,
      targetType: preset.targetType,
      targetValue: preset.targetValue,
      primaryTool: preset.primaryTool,
      ports: preset.ports,
      modifiers: preset.modifiers,
      confidence: preset.confidence
    }));
    setOutputData(null);
    setErrorData(null);
    setErrorStatus(null);
  };

  const handleFormSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setOutputData(null);
    setErrorData(null);
    setErrorStatus(null);

    // Parse ports array from string
    const portList = formData.ports
      ? formData.ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p))
      : [];

    // Construct PlanRequest according to existing backend API contract
    const payload = {
      session_id: formData.sessionId || 'demo-sess-001',
      intent: formData.intent,
      target_type: formData.targetType,
      target_value: formData.targetValue,
      primary_tool: formData.primaryTool,
      confidence: formData.confidence,
      tool_parameters: {
        flags: formData.modifiers || [],
        ports: portList
      }
    };

    // Stage progression animation
    setCurrentStage('interpreter');
    await new Promise(r => setTimeout(r, 150));
    setCurrentStage('rag');
    await new Promise(r => setTimeout(r, 150));
    setCurrentStage('llm');

    const result = await generatePlan(payload, apiKey);

    if (result.success) {
      setCurrentStage('safety');
      await new Promise(r => setTimeout(r, 100));
      setCurrentStage('validator');
      await new Promise(r => setTimeout(r, 100));
      setCurrentStage('output');

      setOutputData(result.data);
    } else {
      setErrorStatus(result.status);
      setErrorData(result.errorData);

      if (result.status === 422 || result.errorData?.stage === 'command_validator') {
        setCurrentStage('validator');
      } else {
        setCurrentStage('safety');
      }
    }

    setLoading(false);
  };

  return (
    <div className="app-container">
      {/* Header */}
      <Header
        apiKey={apiKey}
        onOpenKeyModal={() => setIsKeyModalOpen(true)}
      />

      {/* System Status Panel */}
      <StatusPanel />

      {/* Demo Presets Bar */}
      <Presets onSelectPreset={handleSelectPreset} />

      {/* Main Grid: Input Form + Visualizer / Output */}
      <div className="main-layout">
        <PlannerForm
          formData={formData}
          setFormData={setFormData}
          onSubmit={handleFormSubmit}
          loading={loading}
        />

        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Pipeline Stepper */}
          <PipelineVisualizer
            currentStage={currentStage}
            isError={!!errorData}
            errorStage={errorStatus === 422 ? 'validator' : 'safety'}
          />

          {/* Successful Output Display */}
          <PlannerOutput data={outputData} />

          {/* Error / Safety Rejection Display */}
          <SafetyAlert errorData={errorData} status={errorStatus} />

          {/* Metrics Overview Panel */}
          <MetricsPanel apiKey={apiKey} />
        </div>
      </div>

      {/* API Key Modal */}
      <ApiKeyModal
        isOpen={isKeyModalOpen}
        currentKey={apiKey}
        onSave={handleSaveApiKey}
        onClose={() => setIsKeyModalOpen(false)}
      />
    </div>
  );
}
