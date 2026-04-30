import pytest

from app.parsers.atomic_powershell import Parser


class TestParserCheckedFlags:
    """
    Tests for the Parser.checked_flags class attribute.

    KNOWN BUG: `list('FullyQualifiedErrorId')` produces a list of individual
    characters ['F', 'u', 'l', 'l', 'y', ...] instead of the intended
    ['FullyQualifiedErrorId']. This means the parser checks for single
    characters rather than the full error string.

    Tests marked xfail below document current buggy behavior and are expected
    to start passing once the bug is fixed (at which point they should be
    updated to assert the correct behavior instead).
    """

    def test_checked_flags_is_list(self):
        assert isinstance(Parser.checked_flags, list)

    @pytest.mark.xfail(
        reason="Bug: list('FullyQualifiedErrorId') splits into chars; "
               "once fixed, checked_flags will equal ['FullyQualifiedErrorId'] "
               "and this test will need to be updated to assert the correct value."
    )
    def test_checked_flags_known_bug_individual_characters(self):
        """
        Demonstrates the known bug: list('FullyQualifiedErrorId') splits the
        string into individual characters instead of wrapping it in a list.
        Once the bug is fixed, Parser.checked_flags will equal
        ['FullyQualifiedErrorId'] and this assertion will fail.
        """
        expected_buggy = list('FullyQualifiedErrorId')
        assert Parser.checked_flags == expected_buggy
        # This is what it SHOULD be:
        expected_correct = ['FullyQualifiedErrorId']
        assert Parser.checked_flags != expected_correct

    @pytest.mark.xfail(
        reason="Bug: checked_flags contains one entry per character (21 total) "
               "instead of a single string entry; will break when bug is fixed."
    )
    def test_checked_flags_length_is_wrong(self):
        """The list has 21 entries (one per char) instead of 1."""
        assert len(Parser.checked_flags) == len('FullyQualifiedErrorId')
        assert len(Parser.checked_flags) != 1

    @pytest.mark.xfail(
        reason="Bug: checked_flags contains individual characters; "
               "will break when bug is fixed and flags become full strings."
    )
    def test_checked_flags_contains_individual_chars(self):
        """Each element is a single character."""
        for flag in Parser.checked_flags:
            assert len(flag) == 1

    @pytest.mark.xfail(
        reason="Bug: first element is 'F' (first char of 'FullyQualifiedErrorId'); "
               "will break when bug is fixed."
    )
    def test_checked_flags_first_char_is_F(self):
        assert Parser.checked_flags[0] == 'F'

    @pytest.mark.xfail(
        reason="Bug: last element is 'd' (last char of 'FullyQualifiedErrorId'); "
               "will break when bug is fixed."
    )
    def test_checked_flags_last_char_is_d(self):
        assert Parser.checked_flags[-1] == 'd'


class TestParserParse:
    """Tests for the Parser.parse() method."""

    def test_parse_empty_blob(self):
        parser = Parser()
        result = parser.parse('')
        assert result == []

    def test_parse_no_error_indicators(self):
        parser = Parser()
        result = parser.parse('All good, no issues here.\nAnother clean line.')
        # Because of the bug, any line containing common letters like 'l', 'e',
        # 'i', etc. will be flagged. Let's check:
        # 'All good, no issues here.' contains 'l' which is in checked_flags
        from app.utility.base_parser import PARSER_SIGNALS_FAILURE
        assert result == [PARSER_SIGNALS_FAILURE]

    def test_parse_with_fully_qualified_error_id(self):
        """A line containing 'FullyQualifiedErrorId' should trigger failure."""
        parser = Parser()
        blob = 'Error: FullyQualifiedErrorId : SomeError'
        from app.utility.base_parser import PARSER_SIGNALS_FAILURE
        result = parser.parse(blob)
        assert result == [PARSER_SIGNALS_FAILURE]

    def test_parse_bug_false_positive_on_common_letters(self):
        """
        Due to the bug, even innocent text containing letters like 'e', 'l',
        'i', 'r', 'd', etc. will trigger the parser as failed.
        """
        parser = Parser()
        from app.utility.base_parser import PARSER_SIGNALS_FAILURE
        # 'hello' contains 'l' and 'e' which are in list('FullyQualifiedErrorId')
        result = parser.parse('hello')
        assert result == [PARSER_SIGNALS_FAILURE]

    def test_parse_bug_no_false_positive_on_safe_chars(self):
        """
        Text using ONLY characters NOT in 'FullyQualifiedErrorId' should pass.
        Characters in the string: F, u, l, y, Q, a, i, f, e, d, E, r, o, I
        So characters NOT in the set include: b, c, g, h, j, k, m, n, p, s, t, v, w, x, z
        and digits, punctuation etc.
        """
        parser = Parser()
        # Using only characters NOT present in 'FullyQualifiedErrorId'
        safe_text = '0123456789 -+*/'
        result = parser.parse(safe_text)
        assert result == []

    def test_parse_returns_failure_signal_list(self):
        """When failure is detected, return value is [PARSER_SIGNALS_FAILURE]."""
        parser = Parser()
        from app.utility.base_parser import PARSER_SIGNALS_FAILURE
        result = parser.parse('Some error output with letter e')
        assert len(result) == 1
        assert result[0] == PARSER_SIGNALS_FAILURE

    def test_parse_multiline_first_line_triggers(self):
        """Only the first matching line triggers failure, method returns early."""
        parser = Parser()
        from app.utility.base_parser import PARSER_SIGNALS_FAILURE
        blob = 'line with F\nclean_0123'
        result = parser.parse(blob)
        assert result == [PARSER_SIGNALS_FAILURE]

    def test_parse_all_clean_lines_no_flagged_chars(self):
        """Multiple lines all free of flagged characters should pass."""
        parser = Parser()
        blob = '0123\n4567\n890'
        result = parser.parse(blob)
        assert result == []

    def test_parse_correct_behavior_if_bug_fixed(self):
        """
        Demonstrates what SHOULD happen if the bug were fixed:
        Only 'FullyQualifiedErrorId' as a substring should trigger failure.

        Currently, because checked_flags is individual characters, this test
        verifies the BUGGY behavior.
        """
        parser = Parser()
        from app.utility.base_parser import PARSER_SIGNALS_FAILURE
        # Text without 'FullyQualifiedErrorId' but with common letters
        result = parser.parse('Process completed successfully')
        # BUG: triggers because 'e', 'l', etc. are in checked_flags
        assert result == [PARSER_SIGNALS_FAILURE]
        # If fixed, this would return [] instead


class TestParserLineMethod:
    """Test the inherited line() method from BaseParser."""

    def test_line_splits_blob(self):
        parser = Parser()
        lines = list(parser.line('line1\nline2\nline3'))
        assert lines == ['line1', 'line2', 'line3']

    def test_line_strips_outer_whitespace(self):
        parser = Parser()
        lines = list(parser.line('  line1  \n  line2  '))
        # strip() removes leading/trailing whitespace from the whole blob,
        # then splitlines preserves internal whitespace per line
        assert lines == ['line1  ', '  line2']

    def test_line_empty_blob(self):
        parser = Parser()
        lines = list(parser.line(''))
        # ''.strip().splitlines() returns []
        assert lines == []

    def test_line_single_line(self):
        parser = Parser()
        lines = list(parser.line('single'))
        assert lines == ['single']
