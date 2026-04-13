import React, { useState, useEffect } from 'react';
import CircuitCanvas from './components/CircuitCanvas';
import CardLibrary from './components/CardLibrary';
import CardGenerator from './components/CardGenerator';
import { CircuitCard } from './types/CircuitTypes';
import { defaultCards } from './data/defaultCards';

const App: React.FC = () => {
  const [availableCards, setAvailableCards] = useState<CircuitCard[]>(defaultCards);
  const [stackedCards, setStackedCards] = useState<CircuitCard[]>([]);
  const [apiResponse, setApiResponse] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [pqcMode, setPqcMode] = useState<boolean>(false);
  const [pqcStatus, setPqcStatus] = useState<'checking' | 'online' | 'offline'>('checking');
  const [pqcKeypair, setPqcKeypair] = useState<{ publicKey: string; secretKey: string } | null>(null);
  
  const addCardToStack = (card: CircuitCard) => {
    setStackedCards([...stackedCards, { ...card, id: `${card.id}-${Date.now()}` }]);
  };
  
  const addCardToLibrary = (card: CircuitCard) => {
    setAvailableCards([...availableCards, card]);
  };
  
  const removeCardFromStack = (index: number) => {
    const newStack = [...stackedCards];
    newStack.splice(index, 1);
    setStackedCards(newStack);
  };
  
  // Check PQC sidecar availability on mount
  useEffect(() => {
    fetch('/api/pqc/status')
      .then(r => r.ok ? setPqcStatus('online') : setPqcStatus('offline'))
      .catch(() => setPqcStatus('offline'));
  }, []);

  const clearStack = () => {
    setStackedCards([]);
    setApiResponse(null);
    setPqcKeypair(null);
  };

  const hasPqCards = stackedCards.some(c =>
    c.type === 'lattice' || c.type === 'code_based' || c.type === 'hash_based'
  );

  const finalizePqc = async () => {
    if (stackedCards.length === 0) {
      alert('Please add at least one card to the stack before finalizing.');
      return;
    }
    setIsLoading(true);
    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      const apiKey = (window as any).__FOLD_API_KEY || process.env.REACT_APP_API_KEY;
      if (apiKey) headers['X-API-Key'] = apiKey;

      // Step 1: generate classical analysis
      const analysisResp = await fetch('/api/generate_encryption', {
        method: 'POST',
        headers,
        body: JSON.stringify({ cards: stackedCards, timestamp: new Date().toISOString() }),
      });
      if (!analysisResp.ok) throw new Error(`Analysis failed: ${analysisResp.status}`);
      const analysisData = await analysisResp.json();

      // Step 2: generate PQ keypair bound to circuit
      const keypairResp = await fetch('/api/pqc/keypair', {
        method: 'POST',
        headers,
        body: JSON.stringify({ circuit_analysis: analysisData.analysis }),
      });
      if (!keypairResp.ok) throw new Error(`PQC keypair failed: ${keypairResp.status}`);
      const keypairData = await keypairResp.json();
      setPqcKeypair({ publicKey: keypairData.public_key, secretKey: keypairData.secret_key });

      // Step 3: test encrypt round-trip
      const encResp = await fetch('/api/pqc/encrypt', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          circuit_analysis: analysisData.analysis,
          public_key: keypairData.public_key,
          plaintext: 'Post-quantum test from circuit stack',
        }),
      });
      if (!encResp.ok) throw new Error(`PQC encrypt failed: ${encResp.status}`);
      const encData = await encResp.json();

      const decResp = await fetch('/api/pqc/decrypt', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          circuit_analysis: analysisData.analysis,
          secret_key: keypairData.secret_key,
          kem_ciphertext: encData.kem_ciphertext,
          payload: encData.payload,
        }),
      });
      if (!decResp.ok) throw new Error(`PQC decrypt failed: ${decResp.status}`);
      const decData = await decResp.json();

      const output = [
        '# Post-Quantum Encryption Result',
        `# Algorithm: ${keypairData.params?.kem_algorithm || 'ML-KEM-768'}`,
        `# NIST Standard: ${keypairData.params?.nist_standard || 'FIPS 203'}`,
        `# Symmetric: ${keypairData.params?.symmetric || 'AES-256-GCM'}`,
        `# Circuit Seed: ${keypairData.params?.circuit_seed || 'N/A'}`,
        `# PQ Secure: ${keypairData.params?.pq_secure ? 'YES' : 'NO'}`,
        '',
        '# --- Keypair ---',
        `public_key  = "${keypairData.public_key.substring(0, 64)}..."  # ${keypairData.public_key.length} chars (base64)`,
        `secret_key  = "${keypairData.secret_key.substring(0, 64)}..."  # ${keypairData.secret_key.length} chars (base64)`,
        '',
        '# --- Encrypt ---',
        `kem_ciphertext = "${encData.kem_ciphertext.substring(0, 64)}..."`,
        `payload        = "${encData.payload.substring(0, 64)}..."`,
        '',
        '# --- Decrypt (round-trip verified) ---',
        `plaintext = "${decData.plaintext}"`,
        '',
        '# --- Classical Algorithm (hybrid) ---',
        analysisData.algorithm,
      ].join('\n');
      setApiResponse(output);
    } catch (error) {
      console.error('PQC finalize error:', error);
      setApiResponse(`Error: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setIsLoading(false);
    }
  };
  
  const finalizeCircuit = async () => {
    if (stackedCards.length === 0) {
      alert('Please add at least one card to the stack before finalizing.');
      return;
    }
    
    setIsLoading(true);
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      const apiKey = (window as any).__FOLD_API_KEY || process.env.REACT_APP_API_KEY;
      if (apiKey) {
        headers['X-API-Key'] = apiKey;
      }

      const response = await fetch('/api/generate_encryption', {
        method: 'POST',
        headers,
        body: JSON.stringify({ 
          cards: stackedCards,
          timestamp: new Date().toISOString()
        })
      });
      
      if (!response.ok) {
        throw new Error(`API responded with status: ${response.status}`);
      }
      
      const data = await response.json();
      setApiResponse(data.algorithm);
    } catch (error) {
      console.error('Error finalizing circuit:', error);
      setApiResponse(`Error: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <div className="container">
      <h1>Circuit Card Simulator</h1>
      <p>Visualize stackable circuit cards with matrix logic and predefined mesh layer interactions</p>
      
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={pqcMode}
            onChange={(e) => setPqcMode(e.target.checked)}
            disabled={pqcStatus !== 'online'}
            style={{ width: '18px', height: '18px', accentColor: '#e44a8d' }}
          />
          <span style={{ fontWeight: 600 }}>Post-Quantum Mode</span>
        </label>
        <span style={{
          fontSize: '0.8em',
          padding: '2px 8px',
          borderRadius: '4px',
          backgroundColor: pqcStatus === 'online' ? '#1a3a1a' : pqcStatus === 'checking' ? '#3a3a1a' : '#3a1a1a',
          color: pqcStatus === 'online' ? '#4ae44a' : pqcStatus === 'checking' ? '#e4e44a' : '#e44a4a',
        }}>
          PQC: {pqcStatus === 'online' ? 'ML-KEM-768 ready' : pqcStatus === 'checking' ? 'checking...' : 'sidecar offline'}
        </span>
        {hasPqCards && !pqcMode && pqcStatus === 'online' && (
          <span style={{ fontSize: '0.8em', color: '#e4a44a' }}>
            Lattice cards detected — enable PQ mode for post-quantum encryption
          </span>
        )}
      </div>

      <div className="canvas-container">
        <CircuitCanvas stackedCards={stackedCards} />
      </div>
      
      <div className="controls">
        <button onClick={clearStack}>Clear Stack</button>
        {pqcMode ? (
          <button
            className="finalize-button"
            onClick={finalizePqc}
            disabled={isLoading}
            style={{
              backgroundColor: '#e44a8d',
              marginLeft: '10px'
            }}
          >
            {isLoading ? 'Processing...' : 'FINALIZE (PQ)'}
          </button>
        ) : (
          <button 
            className="finalize-button" 
            onClick={finalizeCircuit}
            disabled={isLoading}
            style={{
              backgroundColor: '#6a4aa5',
              marginLeft: '10px'
            }}
          >
            {isLoading ? 'Processing...' : 'FINALIZE'}
          </button>
        )}
        <span>{stackedCards.length} cards in stack</span>
      </div>
      
      {apiResponse && (
        <div className="algorithm-response">
          <h3>Generated Encryption Algorithm</h3>
          <pre style={{ 
            backgroundColor: '#1e1e1e', 
            padding: '15px', 
            borderRadius: '5px',
            overflowX: 'auto',
            color: '#e0e0e0'
          }}>
            {apiResponse}
          </pre>
        </div>
      )}
      
      <div className="library-section" style={{ marginTop: '20px' }}>
        <h2>Card Generator</h2>
        <CardGenerator addCardToLibrary={addCardToLibrary} />
        
        <h2 style={{ marginTop: '20px' }}>Card Library</h2>
        <CardLibrary 
          availableCards={availableCards} 
          addCardToStack={addCardToStack} 
        />
      </div>
    </div>
  );
};

export default App; 