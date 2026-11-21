"""kev-triage test package.

ResourceWarning is silenced: the mock HTTP server's sockets are closed by the
interpreter at a time the test runner still watches stderr, and that noise says
nothing about the tool.
"""

import warnings

warnings.filterwarnings("ignore", category=ResourceWarning)
