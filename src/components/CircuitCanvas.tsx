import React, { useRef, useEffect } from 'react';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls';
import { CircuitCard } from '../types/CircuitTypes';

interface CircuitCanvasProps {
  stackedCards: CircuitCard[];
}

const CircuitCanvas: React.FC<CircuitCanvasProps> = ({ stackedCards }) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const sceneRef = useRef<THREE.Scene | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const controlsRef = useRef<OrbitControls | null>(null);
  const cardsGroupRef = useRef<THREE.Group | null>(null);

  // Initialize the 3D scene
  useEffect(() => {
    if (!mountRef.current) return;

    // Create scene
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x121212);
    sceneRef.current = scene;

    // Create camera
    const camera = new THREE.PerspectiveCamera(
      75,
      mountRef.current.clientWidth / mountRef.current.clientHeight,
      0.1,
      1000
    );
    camera.position.set(0, 2, 4);
    cameraRef.current = camera;

    // Create renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(mountRef.current.clientWidth, mountRef.current.clientHeight);
    renderer.shadowMap.enabled = true;
    mountRef.current.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // Add lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
    scene.add(ambientLight);

    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(5, 10, 7);
    directionalLight.castShadow = true;
    scene.add(directionalLight);

    // Add grid for reference
    const gridHelper = new THREE.GridHelper(10, 10, 0x444444, 0x222222);
    scene.add(gridHelper);

    // Create a group to hold all cards
    const cardsGroup = new THREE.Group();
    scene.add(cardsGroup);
    cardsGroupRef.current = cardsGroup;

    // Add orbit controls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.1;
    controlsRef.current = controls;

    // Animation loop
    const animate = () => {
      requestAnimationFrame(animate);
      
      if (controlsRef.current) {
        controlsRef.current.update();
      }
      
      if (rendererRef.current && cameraRef.current && sceneRef.current) {
        rendererRef.current.render(sceneRef.current, cameraRef.current);
      }
    };
    
    animate();

    // Handle window resize
    const handleResize = () => {
      if (!mountRef.current || !cameraRef.current || !rendererRef.current) return;
      
      const width = mountRef.current.clientWidth;
      const height = mountRef.current.clientHeight;
      
      cameraRef.current.aspect = width / height;
      cameraRef.current.updateProjectionMatrix();
      
      rendererRef.current.setSize(width, height);
    };

    window.addEventListener('resize', handleResize);

    // Cleanup
    return () => {
      window.removeEventListener('resize', handleResize);
      
      if (mountRef.current && rendererRef.current) {
        mountRef.current.removeChild(rendererRef.current.domElement);
      }
      
      // Dispose of Three.js objects to free memory
      if (rendererRef.current) {
        rendererRef.current.dispose();
      }
    };
  }, []);

  // Update cards when stackedCards changes
  useEffect(() => {
    if (!cardsGroupRef.current || !sceneRef.current) return;

    // Clear existing cards
    while (cardsGroupRef.current.children.length > 0) {
      const object = cardsGroupRef.current.children[0];
      cardsGroupRef.current.remove(object);
    }

    // Add card for each in stack
    let yPosition = 0;
    stackedCards.forEach((card, index) => {
      const cardMesh = createCardMesh(card, yPosition);
      if (cardsGroupRef.current) {
        cardsGroupRef.current.add(cardMesh);
      }
      yPosition += card.height + 0.05; // Add a small gap between cards
    });

  }, [stackedCards]);

  // Create a mesh for a single card
  const createCardMesh = (card: CircuitCard, yPosition: number): THREE.Group => {
    const cardGroup = new THREE.Group();
    
    // Create the card base
    const geometry = new THREE.BoxGeometry(2, card.height, 2);
    const material = new THREE.MeshStandardMaterial({ 
      color: new THREE.Color(card.color),
      transparent: true,
      opacity: 0.8,
      metalness: 0.2,
      roughness: 0.7
    });
    
    const cardMesh = new THREE.Mesh(geometry, material);
    cardMesh.position.y = yPosition + card.height / 2;
    cardMesh.castShadow = true;
    cardMesh.receiveShadow = true;
    cardGroup.add(cardMesh);
    
    // Add nodes as small spheres
    card.nodes.forEach(node => {
      const nodeGeometry = new THREE.SphereGeometry(0.05, 16, 16);
      const nodeMaterial = new THREE.MeshStandardMaterial({ 
        color: node.type === 'input' ? 0x4a90e2 : 
               node.type === 'output' ? 0xe24a4a : 0x4ae29a 
      });
      
      const nodeMesh = new THREE.Mesh(nodeGeometry, nodeMaterial);
      // Convert from normalized coordinates to mesh coordinates
      nodeMesh.position.set(
        (node.x - 0.5) * 2,
        yPosition + card.height,
        (node.y - 0.5) * 2
      );
      
      cardGroup.add(nodeMesh);
    });
    
    // Add connections within the card
    if (card.matrixConnections) {
      card.matrixConnections.forEach(connection => {
        if (connection.active) {
          const startPoint = new THREE.Vector3(
            (connection.fromX - 0.5) * 2,
            yPosition + card.height / 2,
            (connection.fromY - 0.5) * 2
          );
          
          const endPoint = new THREE.Vector3(
            (connection.toX - 0.5) * 2,
            yPosition + card.height / 2,
            (connection.toY - 0.5) * 2
          );
          
          const connectionGeometry = new THREE.BufferGeometry().setFromPoints([startPoint, endPoint]);
          const connectionMaterial = new THREE.LineBasicMaterial({ color: 0xffff00 });
          const line = new THREE.Line(connectionGeometry, connectionMaterial);
          
          cardGroup.add(line);
        }
      });
    }
    
    // Add mesh interaction points
    card.meshInteractionPoints.forEach(point => {
      const pointGeometry = new THREE.SphereGeometry(0.03, 8, 8);
      const pointMaterial = new THREE.MeshStandardMaterial({ color: 0xffffff });
      
      const pointMesh = new THREE.Mesh(pointGeometry, pointMaterial);
      pointMesh.position.set(
        (point.x - 0.5) * 2,
        yPosition,
        (point.y - 0.5) * 2
      );
      
      cardGroup.add(pointMesh);
    });
    
    return cardGroup;
  };

  return <div ref={mountRef} style={{ width: '100%', height: '100%' }} />;
};

export default CircuitCanvas; 