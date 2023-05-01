from pygments import highlight
from pygments.lexers import SMLLexer
from pygments.formatters import HtmlFormatter


def test_CVE_2021_20270():
    code = 'exception'
    print(highlight(code, SMLLexer(), HtmlFormatter()))
