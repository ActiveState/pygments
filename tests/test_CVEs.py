"""
    Regression tests for fixed CVEs
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: Copyright 2006-2019 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

import os
import time

import pytest

from pygments import highlight
from pygments.lexers import SMLLexer, get_lexer_by_name
from pygments.formatters import HtmlFormatter


def _pick_timer():
    """A monotonically increasing clock, in seconds.

    `time.time()` is not usable here: it can jump backwards when the system
    clock is adjusted, which was observed on the machine these budgets were
    measured on.  `time.monotonic()` would do but is Python 3.3+, and
    `time.clock()` is gone in Python 3.8 (and deprecated before that, which
    pytest.ini turns into an error).  So on Python 2.7 fall back to process
    CPU time, which cannot go backwards and is anyway the thing a ReDoS
    actually burns.
    """
    monotonic = getattr(time, 'monotonic', None)
    if monotonic is not None:
        return monotonic
    if any(os.times()[:2]):  # POSIX; zero on some other platforms
        return lambda: sum(os.times()[:2])
    return time.time


_timer = _pick_timer()


def test_CVE_2021_20270():
    code = 'exception'
    print(highlight(code, SMLLexer(), HtmlFormatter()))


# CVE-2021-27291: a number of lexers carried regexes with exponential or
# cubic worst-case complexity.  The payloads below are the ones published
# with the advisory
# (https://gist.github.com/b-c-ds/b1a2cc0c68a35c57188575eb496de5ce); each
# needed between 4 and 110 seconds before the fix and is near-instant
# afterwards.  The Ceylon payload is twice the advisory's length so that
# it too is comfortably over the budget when unpatched.
_REDOS_PAYLOADS = [
    ('adl', 'language\n <' + '0' * 30),
    ('cadl', '<' + '0' * 30),
    ('odin', '<' + '0' * 30),
    ('ceylon', '"' + '`' * 6912),
    ('evoque', '$evoque{' + 'a' * 3456),
    ('factor', '"""' + ' ' * 3456),
    ('logos', '%new(' + ' ' * 3456),
    ('matlab', 'function' + ' ' * 3456),
    ('octave', 'function' + ' ' * 3456),
    ('scilab', 'function' + ' ' * 3456),
    ('vcl', 'backend x{.a=' + ' ' * 3456),
]

# Generous enough not to be flaky on a loaded machine, small enough that
# every unpatched payload (>= 34s) blows through it.
_REDOS_TIME_LIMIT = 5.0


@pytest.mark.parametrize('alias, payload', _REDOS_PAYLOADS)
def test_CVE_2021_27291(alias, payload):
    lexer = get_lexer_by_name(alias)
    start = _timer()
    for _ in lexer.get_tokens(payload):  # drained, not collected
        pass
    elapsed = _timer() - start
    assert elapsed < _REDOS_TIME_LIMIT, \
        'the %s lexer took %.1fs on the CVE-2021-27291 payload' % (
            alias, elapsed)
