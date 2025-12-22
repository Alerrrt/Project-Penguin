from typing import Dict, List, Optional, Any
import asyncio
from datetime import datetime
import logging
from collections import deque

logger = logging.getLogger(__name__)

class MessageQueue:
    def __init__(self, connection_manager: Any, max_queue_size: int = 1000):
        """
        Initialize message queue.
        
        Args:
            connection_manager: The WebSocket connection manager instance.
            max_queue_size: Maximum number of messages to store per client
        """
        self.connection_manager = connection_manager
        self.queues: Dict[str, deque] = {}
        self.max_queue_size = max_queue_size
        self.processing = False
        self._lock = asyncio.Lock()

    async def enqueue(self, client_id: str, message: Any, options: Optional[Dict] = None):
        """
        Add a message to the queue for a specific client.
        
        Args:
            client_id: The ID of the client.
            message: Message to queue
            options: Optional message processing options
        """
        async with self._lock:
            if client_id not in self.queues:
                self.queues[client_id] = deque(maxlen=self.max_queue_size)
            
            # Add message to queue
            self.queues[client_id].append({
                "message": message,
                "options": options or {},
                "timestamp": datetime.now()
            })
            
            # Start processing if not already running
            if not self.processing:
                self.processing = True
                asyncio.create_task(self._process_queues())

    async def _process_queues(self):
        """Process all message queues."""
        try:
            while True:
                # Check if there are any messages to process
                if not any(self.queues.values()):
                    self.processing = False
                    break
                
                # Process each queue
                for client_id, queue in list(self.queues.items()):
                    if not queue:
                        continue
                    
                    try:
                        # Get next message
                        message_data = queue[0]
                        message = message_data["message"]
                        options = message_data["options"]
                        
                        # Get WebSocket connections
                        websockets = self._get_websockets(client_id)
                        if not websockets:
                            # Remove queue if WebSocket is no longer available
                            del self.queues[client_id]
                            continue
                        
                        # Process message based on options
                        if options.get("throttle", False):
                            # Throttle messages
                            await asyncio.sleep(options.get("throttle_delay", 0.1))
                        
                        if options.get("batch", False):
                            # Batch messages
                            if len(queue) < options.get("batch_size", 10):
                                continue
                        
                        # Send message to all connections for the client
                        for websocket in websockets:
                            await websocket.send_json({
                                "type": message.type,
                                "timestamp": message.timestamp.isoformat(),
                                "data": message.data
                            })
                        
                        # Remove processed message
                        queue.popleft()
                        
                    except Exception as e:
                        logger.error(f"Error processing message for client {client_id}: {e}")
                        # Remove failed message
                        if queue:
                            queue.popleft()
                
                # Small delay to prevent CPU spinning
                await asyncio.sleep(0.01)
                
        except Exception as e:
            logger.error(f"Error in message queue processing: {e}")
            self.processing = False

    def _get_websockets(self, client_id: str) -> Optional[List[Any]]:
        """
        Get WebSocket connections from client ID using the connection manager.
        """
        return self.connection_manager.active_connections.get(client_id)

    def clear_queue(self, client_id: str):
        """
        Clear message queue for a client.
        
        Args:
            client_id: Client identifier
        """
        if client_id in self.queues:
            self.queues[client_id].clear()

    def get_queue_stats(self, client_id: str) -> dict:
        """
        Get queue statistics for a client.
        
        Args:
            client_id: Client identifier
            
        Returns:
            dict: Queue statistics
        """
        queue = self.queues.get(client_id, deque())
        return {
            "queue_size": len(queue),
            "max_queue_size": self.max_queue_size,
            "oldest_message": queue[0]["timestamp"].isoformat() if queue else None,
            "newest_message": queue[-1]["timestamp"].isoformat() if queue else None
        } 
