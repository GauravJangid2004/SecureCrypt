#!/usr/bin/env python3
"""
Run this on the REMOTE server (or second terminal for testing).

    python run_exit_node.py [host] [port]

Default: 0.0.0.0:9090
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from traffic.exit_node import run_exit_node

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9090
    run_exit_node(host, port)