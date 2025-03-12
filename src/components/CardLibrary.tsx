import React from 'react';
import { CircuitCard } from '../types/CircuitTypes';

interface CardLibraryProps {
  availableCards: CircuitCard[];
  addCardToStack: (card: CircuitCard) => void;
}

const CardLibrary: React.FC<CardLibraryProps> = ({ availableCards, addCardToStack }) => {
  return (
    <div className="card-library">
      {availableCards.map(card => (
        <div 
          key={card.id}
          className="library-card"
          style={{
            backgroundColor: card.color,
            padding: '12px',
            borderRadius: '6px',
            boxShadow: '0 2px 4px rgba(0,0,0,0.2)',
            cursor: 'pointer',
            transition: 'all 0.2s ease'
          }}
          onClick={() => addCardToStack(card)}
        >
          <h3 style={{ margin: '0 0 8px 0' }}>{card.name}</h3>
          <p style={{ margin: '0', fontSize: '0.9em', opacity: 0.8 }}>{card.description}</p>
          <div style={{ 
            marginTop: '10px', 
            display: 'flex', 
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <span>Type: {card.type}</span>
            <button 
              style={{
                backgroundColor: 'rgba(255,255,255,0.2)',
                border: 'none',
                padding: '4px 8px',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
              onClick={(e) => {
                e.stopPropagation();
                addCardToStack(card);
              }}
            >
              Add to Stack
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

export default CardLibrary; 