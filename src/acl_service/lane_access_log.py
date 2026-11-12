"""Prevent opaque lane capability paths from appearing in Uvicorn access logs."""
import logging
import re


class LaneAccessLogFilter(logging.Filter):
    def filter(self, record):
        if isinstance(record.args, tuple) and len(record.args) == 5:
            args = list(record.args)
            if isinstance(args[2], str) and args[2].startswith('/api/v1/acl/sociacl/contact-lanes/'):
                args[2] = '/api/v1/acl/sociacl/contact-lanes/[redacted]'
                record.args = tuple(args)
        return True


def install_lane_log_filter():
    logger = logging.getLogger('uvicorn.access')
    if not any(isinstance(f, LaneAccessLogFilter) for f in logger.filters):
        logger.addFilter(LaneAccessLogFilter())
