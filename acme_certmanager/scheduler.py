"""Certificate auto-renewal scheduler."""

import logging
import os
from datetime import datetime
from typing import Dict

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.memory import MemoryJobStore
from apscheduler.executors.asyncio import AsyncIOExecutor

logger = logging.getLogger(__name__)


class CertificateScheduler:
    """Scheduler for automatic certificate renewal."""
    
    def __init__(self, manager):
        """Initialize scheduler."""
        self.manager = manager
        self.scheduler = AsyncIOScheduler(
            jobstores={
                'default': MemoryJobStore()
            },
            executors={
                'default': AsyncIOExecutor()
            },
            job_defaults={
                'coalesce': True,
                'max_instances': 1
            }
        )
        
        # Configuration
        self.check_interval = int(os.getenv('RENEWAL_CHECK_INTERVAL', '86400'))  # 24 hours
        self.threshold_days = int(os.getenv('RENEWAL_THRESHOLD_DAYS', '30'))
        
        # Track renewal jobs
        self.renewal_jobs: Dict[str, str] = {}
    
    def start(self):
        """Start the scheduler."""
        if not self.scheduler.running:
            self.scheduler.start()
            
            # Schedule periodic renewal check
            self.scheduler.add_job(
                self.check_and_renew_certificates,
                'interval',
                seconds=self.check_interval,
                id='renewal_check',
                replace_existing=True
            )
            
            logger.info(f"Scheduler started with check interval: {self.check_interval}s")
    
    def stop(self):
        """Stop the scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Scheduler stopped")
    
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self.scheduler.running
    
    async def check_and_renew_certificates(self):
        """Check and renew expiring certificates."""
        logger.info("Checking certificates for renewal")
        
        try:
            # Get expiring certificates
            expiring = self.manager.get_expiring_certificates(self.threshold_days)
            
            for cert_name, certificate in expiring:
                # Skip if renewal job already scheduled
                if cert_name in self.renewal_jobs:
                    job = self.scheduler.get_job(self.renewal_jobs[cert_name])
                    if job:
                        continue
                
                # Schedule immediate renewal
                job = self.scheduler.add_job(
                    self.renew_certificate,
                    'date',
                    run_date=datetime.now(),
                    args=[cert_name],
                    id=f"renew_{cert_name}_{datetime.now().timestamp()}"
                )
                
                self.renewal_jobs[cert_name] = job.id
                logger.info(f"Scheduled renewal for certificate: {cert_name}")
        
        except Exception as e:
            logger.error(f"Error checking certificates: {e}")
    
    async def renew_certificate(self, cert_name: str):
        """Renew a single certificate."""
        try:
            logger.info(f"Renewing certificate: {cert_name}")
            
            # Perform renewal
            new_cert = self.manager.renew_certificate(cert_name)
            
            if new_cert:
                logger.info(f"Successfully renewed certificate: {cert_name}")
                
                # Update SSL context if server is available
                from .server import https_server
                https_server.update_ssl_context(new_cert)
            else:
                logger.error(f"Failed to renew certificate: {cert_name}")
        
        except Exception as e:
            logger.error(f"Error renewing certificate {cert_name}: {e}")
        
        finally:
            # Remove from tracking
            if cert_name in self.renewal_jobs:
                del self.renewal_jobs[cert_name]
    
    def schedule_renewal(self, cert_name: str, expires_at: datetime):
        """Schedule renewal for a specific certificate."""
        # Calculate renewal time (threshold_days before expiry)
        from datetime import timedelta
        renewal_time = expires_at - timedelta(days=self.threshold_days)
        
        # Don't schedule if already past renewal time
        if renewal_time <= datetime.now():
            # Schedule immediate renewal
            renewal_time = datetime.now()
        
        # Remove existing job if any
        if cert_name in self.renewal_jobs:
            try:
                self.scheduler.remove_job(self.renewal_jobs[cert_name])
            except:
                pass
        
        # Schedule new job
        job = self.scheduler.add_job(
            self.renew_certificate,
            'date',
            run_date=renewal_time,
            args=[cert_name],
            id=f"renew_{cert_name}_{renewal_time.timestamp()}"
        )
        
        self.renewal_jobs[cert_name] = job.id
        logger.info(f"Scheduled renewal for {cert_name} at {renewal_time}")
    
    def cancel_renewal(self, cert_name: str):
        """Cancel scheduled renewal for a certificate."""
        if cert_name in self.renewal_jobs:
            try:
                self.scheduler.remove_job(self.renewal_jobs[cert_name])
                del self.renewal_jobs[cert_name]
                logger.info(f"Cancelled renewal for certificate: {cert_name}")
            except Exception as e:
                logger.error(f"Error cancelling renewal for {cert_name}: {e}")