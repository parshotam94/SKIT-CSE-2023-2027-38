"""
WebSocket handler for real-time WAF monitoring
Streams live detection results to connected clients

NOTE: This handler only BROADCASTS events. It does NOT generate traffic.
Traffic comes from:
- Real /scan API requests
- Demo traffic generator (when demo_mode is enabled in Settings)
"""

import json
from typing import Set, Dict, Any
from fastapi import WebSocket

from utils import WAFLogger
from inference import AnomalyDetector


class ConnectionManager:
    """Manages WebSocket connections"""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.logger = WAFLogger(__name__)

    async def connect(self, websocket: WebSocket):
        """Accept new WebSocket connection"""
        await websocket.accept()
        self.active_connections.add(websocket)
        self.logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        self.active_connections.discard(websocket)
        self.logger.info(f"WebSocket disconnected. Remaining connections: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """
        Broadcast message to all connected clients

        Args:
            message: JSON-serializable message dictionary
        """
        if not self.active_connections:
            return

        message_json = json.dumps(message)

        # Send to all clients, remove failed connections
        disconnected = set()

        for connection in self.active_connections:
            try:
                await connection.send_text(message_json)
            except Exception as e:
                self.logger.error(f"Failed to send message: {e}")
                disconnected.add(connection)

        # Clean up failed connections
        for connection in disconnected:
            self.disconnect(connection)

    async def send_personal(self, message: Dict[str, Any], websocket: WebSocket):
        """
        Send message to specific client

        Args:
            message: JSON-serializable message dictionary
            websocket: Target WebSocket connection
        """
        try:
            await websocket.send_text(json.dumps(message))
        except Exception as e:
            self.logger.error(f"Failed to send personal message: {e}")


class LiveMonitoringHandler:
    """
    Handles live traffic monitoring and detection
    Streams results via WebSocket

    NOTE: Does NOT generate traffic. Only broadcasts events from:
    - Real /scan requests
    - Demo traffic generator (when demo_mode enabled)
    """

    def __init__(self, detector: AnomalyDetector, connection_manager: ConnectionManager):
        """
        Initialize handler

        Args:
            detector: Anomaly detection model
            connection_manager: WebSocket connection manager
        """
        self.detector = detector
        self.manager = connection_manager
        self.logger = WAFLogger(__name__)
        self._running = False

    async def start(self):
        """
        Start handler (passive mode - only broadcasts events, doesn't generate traffic)
        """
        self._running = True
        self.logger.info("Live monitoring handler started (passive relay mode)")

    async def stop(self):
        """Stop handler"""
        self._running = False
        self.logger.info("Live monitoring handler stopped")
