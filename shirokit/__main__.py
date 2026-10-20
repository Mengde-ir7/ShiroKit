#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""支持 ``python -m shirokit`` 直接运行。"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
