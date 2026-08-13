"""
    Regression tests for fixed CVEs
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: Copyright 2006-2019 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

import time

import pytest

from pygments import highlight
from pygments.lexers import SMLLexer, get_lexer_by_name
from pygments.formatters import HtmlFormatter


def test_CVE_2021_20270():
    code = 'exception'
    print(highlight(code, SMLLexer(), HtmlFormatter()))


# CVE-2021-27291: a number of lexers carried regexes with exponential or
# cubic worst-case complexity.  The payloads below are the ones published
# with the advisory
# (https://gist.github.com/b-c-ds/b1a2cc0c68a35c57188575eb496de5ce); each
# needed between 20 and 110 seconds before the fix and is near-instant
# afterwards.
#
# The Matlab/Octave/Scilab payload is deliberately shorter than the
# advisory's 3456 characters: upstream's fix (2.7.4) reduces the cost of
# the function-signature regex by roughly two orders of magnitude but
# leaves it super-linear, so the advisory-sized payload still takes a
# long time.  432 characters is enough to tell patched from unpatched
# (23s -> 0.2s) while keeping the test fast.
_REDOS_PAYLOADS = [
    ('adl', 'language\n <' + '0' * 30),
    ('cadl', '<' + '0' * 30),
    ('odin', '<' + '0' * 30),
    ('ceylon', '"' + '`' * 6912),
    ('evoque', '$evoque{' + 'a' * 3456),
    ('factor', '"""' + ' ' * 3456),
    ('logos', '%new(' + ' ' * 3456),
    ('matlab', 'function' + ' ' * 432),
    ('octave', 'function' + ' ' * 432),
    ('scilab', 'function' + ' ' * 432),
    ('vcl', 'backend x{.a=' + ' ' * 3456),
]

# Generous enough not to be flaky on a loaded machine, small enough that
# every unpatched payload (>= 20s) blows through it.
_REDOS_TIME_LIMIT = 5.0


@pytest.mark.parametrize('alias, payload', _REDOS_PAYLOADS)
def test_CVE_2021_27291(alias, payload):
    lexer = get_lexer_by_name(alias)
    start = time.time()
    list(lexer.get_tokens(payload))
    elapsed = time.time() - start
    assert elapsed < _REDOS_TIME_LIMIT, \
        'the %s lexer took %.1fs on the CVE-2021-27291 payload' % (
            alias, elapsed)
