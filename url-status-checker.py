"""
PingPanda - a friendly command line website health checker.

This file starts the tool, everything else lives in the ``pingpanda`` package:

* ``pingpanda/constants.py`` - the texts and the colours that are printed
* ``pingpanda/models.py``    - the data that is kept about a checked URL
* ``pingpanda/network.py``   - resolving a host and checking a URL
* ``pingpanda/report.py``    - turning the results into the report
* ``pingpanda/cli.py``       - the arguments and what the tool does with them

PingPanda started its life as "Status Checker", written by BLACK-SCORP10
(https://github.com/BLACK-SCORP10/url-status-checker) and later enhanced by
matteocapricci.

Released under the MIT License - see the LICENSE file.
"""

import asyncio

from pingpanda.cli import main

if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
