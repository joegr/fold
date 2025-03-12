import { CircuitCard } from '../types/CircuitTypes';

// Define a simple AND gate card
const andGateCard: CircuitCard = {
  id: 'and-gate',
  name: 'AND Gate',
  description: 'Basic AND logic gate card',
  color: '#4a6fa5',
  type: 'logic',
  height: 0.2,
  nodes: [
    { id: 'in1', x: 0.2, y: 0.3, type: 'input', connections: ['gate1'] },
    { id: 'in2', x: 0.2, y: 0.7, type: 'input', connections: ['gate1'] },
    { id: 'out', x: 0.8, y: 0.5, type: 'output', connections: ['gate1'] }
  ],
  logicGates: [
    { id: 'gate1', type: 'AND', inputs: ['in1', 'in2'], outputs: ['out'], x: 0.5, y: 0.5 }
  ],
  meshInteractionPoints: [
    { id: 'mesh1', x: 0.2, y: 0.3, upConnections: [], downConnections: [] },
    { id: 'mesh2', x: 0.2, y: 0.7, upConnections: [], downConnections: [] },
    { id: 'mesh3', x: 0.8, y: 0.5, upConnections: [], downConnections: [] }
  ]
};

// Define a matrix connection card
const matrixCard: CircuitCard = {
  id: 'matrix-basic',
  name: 'Matrix Card',
  description: 'Basic matrix connection card',
  color: '#a56b4a',
  type: 'matrix',
  height: 0.15,
  nodes: [
    { id: 'in1', x: 0.1, y: 0.2, type: 'input', connections: [] },
    { id: 'in2', x: 0.1, y: 0.4, type: 'input', connections: [] },
    { id: 'in3', x: 0.1, y: 0.6, type: 'input', connections: [] },
    { id: 'in4', x: 0.1, y: 0.8, type: 'input', connections: [] },
    { id: 'out1', x: 0.9, y: 0.2, type: 'output', connections: [] },
    { id: 'out2', x: 0.9, y: 0.4, type: 'output', connections: [] },
    { id: 'out3', x: 0.9, y: 0.6, type: 'output', connections: [] },
    { id: 'out4', x: 0.9, y: 0.8, type: 'output', connections: [] }
  ],
  matrixConnections: [
    { fromX: 0.1, fromY: 0.2, toX: 0.9, toY: 0.8, active: true },
    { fromX: 0.1, fromY: 0.4, toX: 0.9, toY: 0.6, active: true },
    { fromX: 0.1, fromY: 0.6, toX: 0.9, toY: 0.4, active: true },
    { fromX: 0.1, fromY: 0.8, toX: 0.9, toY: 0.2, active: true }
  ],
  meshInteractionPoints: [
    { id: 'mesh1', x: 0.3, y: 0.3, upConnections: [], downConnections: [] },
    { id: 'mesh2', x: 0.3, y: 0.7, upConnections: [], downConnections: [] },
    { id: 'mesh3', x: 0.7, y: 0.3, upConnections: [], downConnections: [] },
    { id: 'mesh4', x: 0.7, y: 0.7, upConnections: [], downConnections: [] }
  ]
};

// Define a hybrid card with both logic and matrix elements
const hybridCard: CircuitCard = {
  id: 'hybrid-basic',
  name: 'Hybrid Card',
  description: 'Card with both logic gates and matrix connections',
  color: '#6aa54a',
  type: 'hybrid',
  height: 0.25,
  nodes: [
    { id: 'in1', x: 0.1, y: 0.3, type: 'input', connections: ['gate1'] },
    { id: 'in2', x: 0.1, y: 0.7, type: 'input', connections: ['gate1'] },
    { id: 'mid', x: 0.5, y: 0.5, type: 'bidirectional', connections: ['gate1'] },
    { id: 'out1', x: 0.9, y: 0.3, type: 'output', connections: [] },
    { id: 'out2', x: 0.9, y: 0.7, type: 'output', connections: [] }
  ],
  logicGates: [
    { id: 'gate1', type: 'AND', inputs: ['in1', 'in2'], outputs: ['mid'], x: 0.3, y: 0.5 }
  ],
  matrixConnections: [
    { fromX: 0.5, fromY: 0.5, toX: 0.9, toY: 0.3, active: true },
    { fromX: 0.5, fromY: 0.5, toX: 0.9, toY: 0.7, active: true }
  ],
  meshInteractionPoints: [
    { id: 'mesh1', x: 0.1, y: 0.3, upConnections: [], downConnections: [] },
    { id: 'mesh2', x: 0.1, y: 0.7, upConnections: [], downConnections: [] },
    { id: 'mesh3', x: 0.5, y: 0.5, upConnections: [], downConnections: [] },
    { id: 'mesh4', x: 0.9, y: 0.3, upConnections: [], downConnections: [] },
    { id: 'mesh5', x: 0.9, y: 0.7, upConnections: [], downConnections: [] }
  ]
};

// Define a mesh interaction card specifically designed for stacking
const meshInteractionCard: CircuitCard = {
  id: 'mesh-connector',
  name: 'Mesh Connector',
  description: 'Specialized card for connecting between layers',
  color: '#8a4aa5',
  type: 'matrix',
  height: 0.1,
  nodes: [
    { id: 'in1', x: 0.2, y: 0.2, type: 'input', connections: [] },
    { id: 'in2', x: 0.2, y: 0.8, type: 'input', connections: [] },
    { id: 'out1', x: 0.8, y: 0.2, type: 'output', connections: [] },
    { id: 'out2', x: 0.8, y: 0.8, type: 'output', connections: [] }
  ],
  matrixConnections: [
    { fromX: 0.2, fromY: 0.2, toX: 0.8, toY: 0.2, active: true },
    { fromX: 0.2, fromY: 0.8, toX: 0.8, toY: 0.8, active: true }
  ],
  meshInteractionPoints: [
    { id: 'mesh1', x: 0.2, y: 0.2, upConnections: ['mesh3'], downConnections: ['mesh3'] },
    { id: 'mesh2', x: 0.2, y: 0.8, upConnections: ['mesh4'], downConnections: ['mesh4'] },
    { id: 'mesh3', x: 0.8, y: 0.2, upConnections: ['mesh1'], downConnections: ['mesh1'] },
    { id: 'mesh4', x: 0.8, y: 0.8, upConnections: ['mesh2'], downConnections: ['mesh2'] }
  ]
};

// Export all default cards
export const defaultCards: CircuitCard[] = [
  andGateCard,
  matrixCard,
  hybridCard,
  meshInteractionCard
]; 