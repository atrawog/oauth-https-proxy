"""Session management for stateful mode."""

import asyncio
import logging
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Dict, Optional
import contextlib

logger = logging.getLogger(__name__)

# Constants
MAX_MESSAGE_QUEUE_SIZE = 100
SESSION_CLEANUP_INTERVAL = 60  # Check every minute


class SessionManager:
    """Manages MCP sessions with message queuing and cleanup."""
    
    def __init__(self, session_timeout: int = 3600):
        """Initialize session manager.
        
        Args:
            session_timeout: Session timeout in seconds (default 1 hour)
        """
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.message_queues: Dict[str, deque] = defaultdict(deque)
        self.session_timeout = session_timeout
        self._cleanup_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        
        # Start cleanup task
        try:
            loop = asyncio.get_running_loop()
            self._cleanup_task = loop.create_task(self._cleanup_loop())
        except RuntimeError:
            # No event loop running yet, will be started later
            pass
    
    async def start_cleanup_task(self):
        """Start the session cleanup background task."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.debug("Started session cleanup task")
    
    async def stop_cleanup_task(self):
        """Stop the session cleanup background task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task
            self._cleanup_task = None
            logger.debug("Stopped session cleanup task")
    
    async def _cleanup_loop(self):
        """Background task to clean up expired sessions."""
        while True:
            try:
                await asyncio.sleep(SESSION_CLEANUP_INTERVAL)
                await self.cleanup_expired_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in session cleanup: {e}")
    
    async def cleanup_expired_sessions(self):
        """Remove expired sessions."""
        current_time = time.time()
        expired_sessions = []
        
        async with self._lock:
            for session_id, session_data in self.sessions.items():
                if current_time - session_data["last_activity"] > self.session_timeout:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                logger.info(f"Cleaning up expired session: {session_id}")
                self._remove_session_internal(session_id)
    
    def create_session(self) -> str:
        """Create a new session and return its ID."""
        session_id = str(uuid.uuid4())
        
        self.sessions[session_id] = {
            "id": session_id,
            "created_at": time.time(),
            "last_activity": time.time(),
            "initialized": False,
            "protocol_version": None,
            "client_info": None,
            "request_count": 0,
            "state": {},  # Session-specific state storage
            "metadata": {}  # Additional metadata
        }
        
        logger.info(f"Created new session: {session_id}")
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data by ID and update activity timestamp."""
        session = self.sessions.get(session_id)
        if session:
            session["last_activity"] = time.time()
        return session
    
    def update_session(self, session_id: str, updates: Dict[str, Any]):
        """Update session data."""
        if session_id in self.sessions:
            self.sessions[session_id].update(updates)
            self.sessions[session_id]["last_activity"] = time.time()
    
    def _remove_session_internal(self, session_id: str):
        """Internal method to remove a session without lock."""
        if session_id in self.sessions:
            del self.sessions[session_id]
        if session_id in self.message_queues:
            del self.message_queues[session_id]
    
    def remove_session(self, session_id: str):
        """Remove a session and its message queue."""
        self._remove_session_internal(session_id)
        logger.debug(f"Removed session: {session_id}")
    
    def queue_message(self, session_id: str, message: Dict[str, Any]):
        """Queue a message for a session."""
        if session_id in self.sessions:
            self.message_queues[session_id].append(message)
            
            # Limit queue size to prevent memory issues
            if len(self.message_queues[session_id]) > MAX_MESSAGE_QUEUE_SIZE:
                self.message_queues[session_id].popleft()
                logger.warning(
                    f"Message queue for session {session_id} exceeded max size, dropping oldest message"
                )
    
    def get_queued_messages(self, session_id: str) -> list[Dict[str, Any]]:
        """Get and clear all queued messages for a session."""
        messages = []
        if session_id in self.message_queues:
            while self.message_queues[session_id]:
                messages.append(self.message_queues[session_id].popleft())
        return messages
    
    def has_queued_messages(self, session_id: str) -> bool:
        """Check if session has queued messages."""
        return session_id in self.message_queues and len(self.message_queues[session_id]) > 0
    
    def get_session_count(self) -> int:
        """Get total number of active sessions."""
        return len(self.sessions)
    
    def get_all_sessions(self, limit: Optional[int] = None) -> list[Dict[str, Any]]:
        """Get all active sessions with optional limit."""
        sessions = []
        for session_id, session_data in self.sessions.items():
            # Create a safe copy without internal state
            safe_session = {
                "session_id": session_id,
                "created_at": session_data.get("created_at"),
                "last_activity": session_data.get("last_activity"),
                "initialized": session_data.get("initialized", False),
                "request_count": session_data.get("request_count", 0),
                "client_info": session_data.get("client_info"),
                "has_queued_messages": self.has_queued_messages(session_id)
            }
            sessions.append(safe_session)
        
        # Sort by last activity (most recent first)
        sessions.sort(key=lambda x: x.get("last_activity", 0), reverse=True)
        
        if limit:
            sessions = sessions[:limit]
        
        return sessions
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get statistics about all sessions."""
        if not self.sessions:
            return {
                "total_sessions": 0,
                "initialized_sessions": 0,
                "average_age_seconds": 0,
                "average_request_count": 0,
                "total_queued_messages": 0
            }
        
        current_time = time.time()
        total_age = 0
        total_requests = 0
        initialized_count = 0
        total_queued = 0
        
        for session_id, session_data in self.sessions.items():
            total_age += current_time - session_data.get("created_at", current_time)
            total_requests += session_data.get("request_count", 0)
            if session_data.get("initialized", False):
                initialized_count += 1
            total_queued += len(self.message_queues.get(session_id, []))
        
        return {
            "total_sessions": len(self.sessions),
            "initialized_sessions": initialized_count,
            "average_age_seconds": total_age / len(self.sessions),
            "average_request_count": total_requests / len(self.sessions),
            "total_queued_messages": total_queued,
            "session_timeout": self.session_timeout
        }
    
    def set_session_state(self, session_id: str, key: str, value: Any):
        """Set a state value for a session."""
        if session_id in self.sessions:
            if "state" not in self.sessions[session_id]:
                self.sessions[session_id]["state"] = {}
            self.sessions[session_id]["state"][key] = value
            self.sessions[session_id]["last_activity"] = time.time()
    
    def get_session_state(self, session_id: str, key: str, default: Any = None) -> Any:
        """Get a state value for a session."""
        if session_id in self.sessions:
            return self.sessions[session_id].get("state", {}).get(key, default)
        return default
    
    def delete_session_state(self, session_id: str, key: str):
        """Delete a state value for a session."""
        if session_id in self.sessions:
            if "state" in self.sessions[session_id] and key in self.sessions[session_id]["state"]:
                del self.sessions[session_id]["state"][key]
                self.sessions[session_id]["last_activity"] = time.time()