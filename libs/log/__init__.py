#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging.config

logging.config.fileConfig("logging.conf", disable_existing_loggers=True)

logger = logging.getLogger("DoHVerifier")
