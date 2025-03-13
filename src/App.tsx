import React, { useState } from 'react';
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
  
  const clearStack = () => {
    setStackedCards([]);
    setApiResponse(null);
  };
  
  const finalizeCircuit = async () => {
    if (stackedCards.length === 0) {
      alert('Please add at least one card to the stack before finalizing.');
      return;
    }
    
    setIsLoading(true);
    try {
      const response = await fetch('/api/generate_encryption', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
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
      
      <div className="canvas-container">
        <CircuitCanvas stackedCards={stackedCards} />
      </div>
      
      <div className="controls">
        <button onClick={clearStack}>Clear Stack</button>
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