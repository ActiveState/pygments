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


# CVE-2026-4539: the ADL metadata GUID rule and the archetype id rule used
# unbounded repeats, so each failed match attempt on a long run of word
# characters backtracked over the whole run.  Scanning the rule at every
# offset of a 20000-character run took about 7s before the fix.
def _rule_matchers(lexer_cls, state, token):
    lexer_cls()  # compiles _tokens
    return [m for m, action, _ in lexer_cls._tokens[state] if action is token]


def _scan_time(matchers, text):
    start = _timer()
    for match in matchers:
        for pos in range(len(text)):
            match(text, pos)
    return _timer() - start


def test_CVE_2026_4539_guid_rule_is_bounded():
    from pygments.lexers.archetype import AdlLexer
    from pygments.token import Literal
    matchers = _rule_matchers(AdlLexer, 'metadata', Literal)
    elapsed = _scan_time(matchers, 'a' * 20000)
    assert elapsed < 1.0, 'GUID rule scan took %.1fs' % elapsed


def test_CVE_2026_4539_archetype_id_rule_is_bounded():
    from pygments.lexers.archetype import AdlLexer
    from pygments.token import Name
    matchers = _rule_matchers(AdlLexer, 'root', Name.Decorator)
    assert matchers
    elapsed = _scan_time(matchers, 'a' * 20000)
    assert elapsed < 1.0, 'archetype id rule scan took %.1fs' % elapsed


def test_CVE_2026_4539_still_lexes_guids_and_ids():
    from pygments.lexers.archetype import AdlLexer
    from pygments.token import Literal, Name
    code = ('archetype (adl_version=1.4; '
            'uid=f2b2a6-2a04-4b6a-9c3e-0f2b4b1e7c5d)\n'
            '    openEHR-EHR-OBSERVATION.blood_pressure.v1\n')
    tokens = list(AdlLexer().get_tokens(code))
    assert (Literal, 'f2b2a6-2a04-4b6a-9c3e-0f2b4b1e7c5d') in tokens
    assert (Name.Decorator,
            '    openEHR-EHR-OBSERVATION.blood_pressure.v1') in tokens
