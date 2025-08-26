#!/usr/bin/env python3
"""
Rebuild Redis log indexes from existing stream entries.

This script scans the logs:all:stream and creates proper Redis indexes
for efficient querying. Run this after deploying the new index-based
logging system.

Usage:
    python scripts/rebuild_log_indexes.py [--hours HOURS]
"""

import asyncio
import os
import sys
import argparse
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.unified_storage import UnifiedStorage
from src.storage.async_log_storage import AsyncLogStorage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    """Main function to rebuild log indexes."""
    parser = argparse.ArgumentParser(description='Rebuild Redis log indexes from stream entries')
    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        help='Number of hours of logs to index (default: 24)'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=1000,
        help='Number of entries to process per batch (default: 1000)'
    )
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Also cleanup old indexes older than 30 days'
    )
    
    args = parser.parse_args()
    
    # Get Redis URL from environment
    redis_url = os.getenv('REDIS_URL')
    if not redis_url:
        redis_password = os.getenv('REDIS_PASSWORD')
        if not redis_password:
            logger.error("REDIS_PASSWORD environment variable not set")
            sys.exit(1)
        redis_url = f"redis://:{redis_password}@redis:6379/0"
    
    logger.info("Connecting to Redis...")
    
    # Initialize storage
    storage = UnifiedStorage(redis_url)
    await storage.initialize_async()
    
    # Get the log storage instance
    if hasattr(storage, 'log_storage') and storage.log_storage:
        log_storage = storage.log_storage
    else:
        # Create log storage directly if not available
        log_storage = AsyncLogStorage(storage.redis_client)
        await log_storage.initialize()
    
    logger.info(f"Starting index rebuild for last {args.hours} hours...")
    
    # Rebuild indexes
    indexed_count = await log_storage.rebuild_indexes(
        hours=args.hours,
        batch_size=args.batch_size
    )
    
    logger.info(f"Successfully indexed {indexed_count} log entries")
    
    # Optionally cleanup old indexes
    if args.cleanup:
        logger.info("Cleaning up old index entries...")
        removed_count = await log_storage.cleanup_old_indexes(days=30)
        logger.info(f"Removed {removed_count} old index entries")
    
    # Show index statistics
    logger.info("Checking index statistics...")
    
    # Count entries in various indexes
    all_count = await storage.redis_client.zcard("log:idx:all")
    error_count = await storage.redis_client.zcard("log:idx:errors")
    
    logger.info(f"Index statistics:")
    logger.info(f"  - Total indexed entries: {all_count}")
    logger.info(f"  - Error entries: {error_count}")
    
    # Count unique IPs
    ip_keys = await storage.redis_client.keys("log:idx:ip:*")
    logger.info(f"  - Unique IPs indexed: {len(ip_keys)}")
    
    # Count unique hostnames
    host_keys = await storage.redis_client.keys("log:idx:host:*")
    logger.info(f"  - Unique hostnames indexed: {len(host_keys)}")
    
    logger.info("Index rebuild complete!")


if __name__ == "__main__":
    asyncio.run(main())