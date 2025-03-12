// Define the node type (connection points on a card)
export interface CircuitNode {
  id: string;
  x: number;  // x position (0-1)
  y: number;  // y position (0-1)
  type: 'input' | 'output' | 'bidirectional';
  connections: string[];  // IDs of nodes this is connected to within the card
}

// Define the logical operation types
export type LogicGateType = 'AND' | 'OR' | 'NOT' | 'XOR' | 'NAND' | 'NOR' | 'BUFFER';

// Define a logic gate component
export interface LogicGate {
  id: string;
  type: LogicGateType;
  inputs: string[];   // Node IDs for inputs
  outputs: string[];  // Node IDs for outputs
  x: number;  // x position (0-1)
  y: number;  // y position (0-1)
}

// Define matrix connections (for matrix logic cards)
export interface MatrixConnection {
  fromX: number;
  fromY: number;
  toX: number;
  toY: number;
  active: boolean;
}

// Define mesh interaction points (for layer interactions)
export interface MeshInteractionPoint {
  id: string;
  x: number;
  y: number;
  upConnections: string[];    // IDs of interaction points on the card above
  downConnections: string[];  // IDs of interaction points on the card below
}

// Define the main circuit card type
export interface CircuitCard {
  id: string;
  name: string;
  description: string;
  color: string;
  type: 'logic' | 'matrix' | 'hybrid';
  nodes: CircuitNode[];
  logicGates?: LogicGate[];
  matrixConnections?: MatrixConnection[];
  meshInteractionPoints: MeshInteractionPoint[];
  height: number;  // Thickness of the card (for 3D visualization)
}

// Define a signal type for simulation
export interface Signal {
  id: string;
  value: boolean;
  sourceNodeId: string;
  targetNodeId: string;
  progress: number;  // 0-1 for animation
}

// Define a stack of cards
export interface CardStack {
  cards: CircuitCard[];
  signals: Signal[];
} 