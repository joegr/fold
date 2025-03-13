import React, { useState } from 'react';
import { CircuitCard, CircuitNode, MatrixConnection, MeshInteractionPoint, LogicGate } from '../types/CircuitTypes';

interface CardGeneratorProps {
  addCardToLibrary: (card: CircuitCard) => void;
}

const CardGenerator: React.FC<CardGeneratorProps> = ({ addCardToLibrary }) => {
  const [name, setName] = useState('Custom Card');
  const [description, setDescription] = useState('User generated card');
  const [cardType, setCardType] = useState<'logic' | 'matrix' | 'hybrid'>('matrix');
  const [color, setColor] = useState('#5a6bff');
  const [height, setHeight] = useState(0.2);
  
  // Node and connection customization
  const [inputNodeCount, setInputNodeCount] = useState(4);
  const [outputNodeCount, setOutputNodeCount] = useState(4);
  const [connectionCount, setConnectionCount] = useState(4);
  const [meshPointCount, setMeshPointCount] = useState(4);
  const [logicGateCount, setLogicGateCount] = useState(1);
  
  // Show/hide the form
  const [isExpanded, setIsExpanded] = useState(false);

  // Generate a random ID for the card
  const generateId = () => {
    return `card-${Math.random().toString(36).substring(2, 9)}`;
  };

  // Handle form submission
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    const newCard = generateCardFromSettings();
    addCardToLibrary(newCard);
    
    // Reset form or keep values as desired
    setName('Custom Card');
    setDescription('User generated card');
    setIsExpanded(false);
  };
  
  // Generate nodes with specified count and type
  const generateNodes = (inputCount: number, outputCount: number): CircuitNode[] => {
    const nodes: CircuitNode[] = [];
    
    // Generate input nodes
    for (let i = 0; i < inputCount; i++) {
      const y = (i + 1) / (inputCount + 1);
      nodes.push({
        id: `input-${i}`,
        x: 0.1,
        y,
        type: 'input',
        connections: []
      });
    }
    
    // Generate output nodes
    for (let i = 0; i < outputCount; i++) {
      const y = (i + 1) / (outputCount + 1);
      nodes.push({
        id: `output-${i}`,
        x: 0.9,
        y,
        type: 'output',
        connections: []
      });
    }
    
    return nodes;
  };
  
  // Generate matrix connections
  const generateMatrixConnections = (
    inputCount: number, 
    outputCount: number, 
    connectionCount: number
  ): MatrixConnection[] => {
    const connections: MatrixConnection[] = [];
    const inputNodes = Array.from({ length: inputCount }, (_, i) => i);
    const outputNodes = Array.from({ length: outputCount }, (_, i) => i);
    
    // Shuffle input and output nodes to create random connections
    inputNodes.sort(() => Math.random() - 0.5);
    outputNodes.sort(() => Math.random() - 0.5);
    
    // Create connections
    const count = Math.min(connectionCount, Math.min(inputCount, outputCount));
    for (let i = 0; i < count; i++) {
      const fromY = (inputNodes[i] + 1) / (inputCount + 1);
      const toY = (outputNodes[i] + 1) / (outputCount + 1);
      
      connections.push({
        fromX: 0.1,
        fromY,
        toX: 0.9,
        toY,
        active: true
      });
    }
    
    return connections;
  };
  
  // Generate mesh interaction points
  const generateMeshPoints = (count: number): MeshInteractionPoint[] => {
    const points: MeshInteractionPoint[] = [];
    
    for (let i = 0; i < count; i++) {
      const x = 0.2 + (i % 3) * 0.3;
      const y = 0.2 + Math.floor(i / 3) * 0.3;
      
      points.push({
        id: `mesh-${i}`,
        x,
        y,
        upConnections: [],
        downConnections: []
      });
    }
    
    return points;
  };
  
  // Generate logic gates
  const generateLogicGates = (count: number): LogicGate[] => {
    const gates: LogicGate[] = [];
    const gateTypes: Array<'AND' | 'OR' | 'XOR' | 'NOT' | 'NAND' | 'NOR' | 'BUFFER'> = 
      ['AND', 'OR', 'XOR', 'NOT', 'NAND', 'NOR', 'BUFFER'];
    
    for (let i = 0; i < count; i++) {
      const gateType = gateTypes[Math.floor(Math.random() * gateTypes.length)];
      
      gates.push({
        id: `gate-${i}`,
        type: gateType,
        inputs: [`input-${i % inputNodeCount}`],
        outputs: [`output-${i % outputNodeCount}`],
        x: 0.5,
        y: 0.2 + (i * 0.6) / Math.max(count, 1)
      });
    }
    
    return gates;
  };
  
  // Generate a complete card from the current settings
  const generateCardFromSettings = (): CircuitCard => {
    const cardId = generateId();
    const nodes = generateNodes(inputNodeCount, outputNodeCount);
    const matrixConnections = generateMatrixConnections(
      inputNodeCount, 
      outputNodeCount,
      connectionCount
    );
    const meshPoints = generateMeshPoints(meshPointCount);
    const logicGates = cardType !== 'matrix' ? generateLogicGates(logicGateCount) : undefined;
    
    return {
      id: cardId,
      name,
      description,
      color,
      type: cardType,
      height,
      nodes,
      logicGates,
      matrixConnections: cardType !== 'logic' ? matrixConnections : undefined,
      meshInteractionPoints: meshPoints
    };
  };

  return (
    <div className="card-generator">
      <div 
        className="card-generator-header"
        onClick={() => setIsExpanded(!isExpanded)}
        style={{
          backgroundColor: '#333',
          padding: '10px 15px',
          borderRadius: '5px',
          marginBottom: isExpanded ? '15px' : '0',
          cursor: 'pointer',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}
      >
        <h3 style={{ margin: 0 }}>Create Custom Card</h3>
        <span>{isExpanded ? '▲' : '▼'}</span>
      </div>
      
      {isExpanded && (
        <form 
          onSubmit={handleSubmit}
          style={{
            backgroundColor: '#222',
            padding: '15px',
            borderRadius: '5px',
            marginBottom: '20px'
          }}
        >
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '5px' }}>
                Card Name:
                <input 
                  type="text" 
                  value={name} 
                  onChange={(e) => setName(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px',
                    backgroundColor: '#333',
                    border: '1px solid #444',
                    borderRadius: '4px',
                    color: 'white'
                  }}
                />
              </label>
              
              <label style={{ display: 'block', marginBottom: '5px', marginTop: '10px' }}>
                Description:
                <input 
                  type="text" 
                  value={description} 
                  onChange={(e) => setDescription(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px',
                    backgroundColor: '#333',
                    border: '1px solid #444',
                    borderRadius: '4px',
                    color: 'white'
                  }}
                />
              </label>
              
              <label style={{ display: 'block', marginBottom: '5px', marginTop: '10px' }}>
                Card Type:
                <select 
                  value={cardType} 
                  onChange={(e) => setCardType(e.target.value as 'logic' | 'matrix' | 'hybrid')}
                  style={{
                    width: '100%',
                    padding: '8px',
                    backgroundColor: '#333',
                    border: '1px solid #444',
                    borderRadius: '4px',
                    color: 'white'
                  }}
                >
                  <option value="logic">Logic</option>
                  <option value="matrix">Matrix</option>
                  <option value="hybrid">Hybrid</option>
                </select>
              </label>
              
              <label style={{ display: 'block', marginBottom: '5px', marginTop: '10px' }}>
                Card Color:
                <input 
                  type="color" 
                  value={color} 
                  onChange={(e) => setColor(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0',
                    height: '40px',
                    backgroundColor: 'transparent',
                    border: '1px solid #444',
                    borderRadius: '4px'
                  }}
                />
              </label>
            </div>
            
            <div>
              <label style={{ display: 'block', marginBottom: '5px' }}>
                Input Nodes:
                <input 
                  type="number" 
                  value={inputNodeCount} 
                  min={1} 
                  max={8}
                  onChange={(e) => setInputNodeCount(parseInt(e.target.value))}
                  style={{
                    width: '100%',
                    padding: '8px',
                    backgroundColor: '#333',
                    border: '1px solid #444',
                    borderRadius: '4px',
                    color: 'white'
                  }}
                />
              </label>
              
              <label style={{ display: 'block', marginBottom: '5px', marginTop: '10px' }}>
                Output Nodes:
                <input 
                  type="number" 
                  value={outputNodeCount} 
                  min={1} 
                  max={8}
                  onChange={(e) => setOutputNodeCount(parseInt(e.target.value))}
                  style={{
                    width: '100%',
                    padding: '8px',
                    backgroundColor: '#333',
                    border: '1px solid #444',
                    borderRadius: '4px',
                    color: 'white'
                  }}
                />
              </label>
              
              <label style={{ display: 'block', marginBottom: '5px', marginTop: '10px' }}>
                Connections:
                <input 
                  type="number" 
                  value={connectionCount} 
                  min={0} 
                  max={Math.min(inputNodeCount, outputNodeCount)}
                  onChange={(e) => setConnectionCount(parseInt(e.target.value))}
                  style={{
                    width: '100%',
                    padding: '8px',
                    backgroundColor: '#333',
                    border: '1px solid #444',
                    borderRadius: '4px',
                    color: 'white'
                  }}
                />
              </label>
              
              <div style={{ display: 'flex', gap: '10px' }}>
                <label style={{ flex: 1, display: 'block', marginBottom: '5px', marginTop: '10px' }}>
                  Mesh Points:
                  <input 
                    type="number" 
                    value={meshPointCount} 
                    min={0} 
                    max={9}
                    onChange={(e) => setMeshPointCount(parseInt(e.target.value))}
                    style={{
                      width: '100%',
                      padding: '8px',
                      backgroundColor: '#333',
                      border: '1px solid #444',
                      borderRadius: '4px',
                      color: 'white'
                    }}
                  />
                </label>
                
                {cardType !== 'matrix' && (
                  <label style={{ flex: 1, display: 'block', marginBottom: '5px', marginTop: '10px' }}>
                    Logic Gates:
                    <input 
                      type="number" 
                      value={logicGateCount} 
                      min={0} 
                      max={4}
                      onChange={(e) => setLogicGateCount(parseInt(e.target.value))}
                      style={{
                        width: '100%',
                        padding: '8px',
                        backgroundColor: '#333',
                        border: '1px solid #444',
                        borderRadius: '4px',
                        color: 'white'
                      }}
                    />
                  </label>
                )}
              </div>
            </div>
          </div>
          
          <label style={{ display: 'block', marginBottom: '5px', marginTop: '15px' }}>
            Card Height:
            <input 
              type="range" 
              value={height} 
              min={0.1} 
              max={0.5} 
              step={0.05}
              onChange={(e) => setHeight(parseFloat(e.target.value))}
              style={{
                width: '100%',
                padding: '8px 0',
                backgroundColor: 'transparent'
              }}
            />
            <span style={{ fontSize: '0.9em', marginLeft: '10px' }}>{height}</span>
          </label>
          
          <div style={{ marginTop: '15px', display: 'flex', justifyContent: 'space-between' }}>
            <button 
              type="button"
              onClick={() => setIsExpanded(false)}
              style={{
                padding: '8px 15px',
                backgroundColor: '#444',
                border: 'none',
                borderRadius: '4px',
                color: 'white',
                cursor: 'pointer'
              }}
            >
              Cancel
            </button>
            
            <button 
              type="submit"
              style={{
                padding: '8px 15px',
                backgroundColor: '#4a90e2',
                border: 'none',
                borderRadius: '4px',
                color: 'white',
                cursor: 'pointer'
              }}
            >
              Generate Card
            </button>
          </div>
        </form>
      )}
    </div>
  );
};

export default CardGenerator; 