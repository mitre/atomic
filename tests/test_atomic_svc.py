import hashlib
import json
import os
import re
import pytest
from collections import defaultdict
from unittest.mock import patch, MagicMock, AsyncMock, mock_open

from app.atomic_svc import AtomicService, ExtractionError, PLATFORMS, EXECUTORS, RE_VARIABLE, PREFIX_HASH_LEN


DUMMY_PAYLOAD_PATH = '/tmp/dummyatomicpayload'
DUMMY_PAYLOAD_CONTENT = 'Dummy payload content.'
PREFIX_HASH_LENGTH = 6


# ============================================================================
# Module-level constants
# ============================================================================

class TestModuleConstants:
    """Verify module-level constants are set correctly."""

    def test_platforms_mapping(self):
        assert PLATFORMS == {'windows': 'windows', 'macos': 'darwin', 'linux': 'linux'}

    def test_executors_mapping(self):
        assert EXECUTORS == {'command_prompt': 'cmd', 'sh': 'sh', 'powershell': 'psh', 'bash': 'sh'}

    def test_re_variable_pattern(self):
        m = RE_VARIABLE.search('#{my_var}')
        assert m is not None
        assert m.group(2) == 'my_var'

    def test_re_variable_no_match(self):
        assert RE_VARIABLE.search('no variables here') is None

    def test_re_variable_multiline(self):
        m = RE_VARIABLE.search('#{multi\nline}')
        assert m is not None
        assert m.group(2) == 'multi\nline'

    def test_prefix_hash_len(self):
        assert PREFIX_HASH_LEN == 6


class TestExtractionError:
    def test_is_exception(self):
        with pytest.raises(ExtractionError):
            raise ExtractionError('test')

    def test_inherits_from_exception(self):
        assert issubclass(ExtractionError, Exception)


# ============================================================================
# AtomicService init / config
# ============================================================================

class TestAtomicSvcConfig:
    def test_svc_config(self, atomic_svc):
        assert atomic_svc.repo_dir == 'plugins/atomic/data/atomic-red-team'
        assert atomic_svc.data_dir == 'plugins/atomic/data'
        assert atomic_svc.payloads_dir == 'plugins/atomic/payloads'

    def test_atomic_dir(self, atomic_svc):
        assert atomic_svc.atomic_dir == os.path.join('plugins', 'atomic')

    def test_technique_to_tactics_default_empty(self, atomic_svc):
        assert isinstance(atomic_svc.technique_to_tactics, defaultdict)
        assert len(atomic_svc.technique_to_tactics) == 0

    def test_processing_debug_default_false(self, atomic_svc):
        assert atomic_svc.processing_debug is False


# ============================================================================
# Path normalization
# ============================================================================

class TestNormalizePath:
    def test_normalize_windows_path(self):
        assert AtomicService._normalize_path('windows\\test\\path', 'windows') == 'windows/test/path'

    def test_normalize_posix_path(self):
        assert AtomicService._normalize_path('linux/test/path', 'linux') == 'linux/test/path'

    def test_normalize_darwin_path(self):
        assert AtomicService._normalize_path('macos/test/path', 'darwin') == 'macos/test/path'

    def test_normalize_windows_no_backslash(self):
        assert AtomicService._normalize_path('already/forward', 'windows') == 'already/forward'

    def test_normalize_empty_string(self):
        assert AtomicService._normalize_path('', 'windows') == ''
        assert AtomicService._normalize_path('', 'linux') == ''

    def test_normalize_nested_backslashes(self):
        assert AtomicService._normalize_path('a\\b\\c\\d', 'windows') == 'a/b/c/d'

    def test_normalize_linux_preserves_backslashes(self):
        # On linux, backslashes are NOT replaced
        assert AtomicService._normalize_path('path\\with\\backslash', 'linux') == 'path\\with\\backslash'


# ============================================================================
# Attachment handling
# ============================================================================

class TestHandleAttachment:
    def test_handle_attachment(self, atomic_svc, generate_dummy_payload, tmp_path):
        atomic_svc.payloads_dir = str(tmp_path / 'payloads')
        os.makedirs(atomic_svc.payloads_dir, exist_ok=True)
        target_hash = hashlib.md5(DUMMY_PAYLOAD_CONTENT.encode()).hexdigest()
        target_name = target_hash[:PREFIX_HASH_LENGTH] + '_dummyatomicpayload'
        target_path = os.path.join(atomic_svc.payloads_dir, target_name)
        assert atomic_svc._handle_attachment(generate_dummy_payload) == target_name
        assert os.path.isfile(target_path)
        with open(target_path, 'r') as f:
            file_data = f.read()
        assert file_data == DUMMY_PAYLOAD_CONTENT

    def test_handle_attachment_name_format(self, atomic_svc, generate_dummy_payload, tmp_path):
        atomic_svc.payloads_dir = str(tmp_path / 'payloads')
        os.makedirs(atomic_svc.payloads_dir, exist_ok=True)
        result = atomic_svc._handle_attachment(generate_dummy_payload)
        parts = result.split('_', 1)
        assert len(parts) == 2
        assert len(parts[0]) == PREFIX_HASH_LENGTH
        assert parts[1] == 'dummyatomicpayload'

    def test_handle_attachment_different_content_different_hash(self, atomic_svc, tmp_path):
        atomic_svc.payloads_dir = str(tmp_path / 'payloads')
        os.makedirs(atomic_svc.payloads_dir, exist_ok=True)
        path1 = str(tmp_path / 'payload_1')
        path2 = str(tmp_path / 'payload_2')
        with open(path1, 'w') as f:
            f.write('content_A')
        with open(path2, 'w') as f:
            f.write('content_B')
        name1 = atomic_svc._handle_attachment(path1)
        name2 = atomic_svc._handle_attachment(path2)
        assert name1 != name2


# ============================================================================
# Multiline command handling
# ============================================================================

class TestHandleMultilineCommands:
    def test_handle_multiline_command_sh(self, multiline_command):
        target = 'command1; command2; command3'
        assert AtomicService._handle_multiline_commands(multiline_command, 'sh') == target

    def test_handle_multiline_command_cmd(self, multiline_command):
        target = 'command1 && command2 && command3'
        assert AtomicService._handle_multiline_commands(multiline_command, 'cmd') == target

    def test_handle_multiline_command_psh(self, multiline_command):
        target = 'command1; command2; command3'
        assert AtomicService._handle_multiline_commands(multiline_command, 'psh') == target

    def test_single_line_sh(self):
        assert AtomicService._handle_multiline_commands('single', 'sh') == 'single'

    def test_single_line_cmd(self):
        assert AtomicService._handle_multiline_commands('single', 'cmd') == 'single'

    def test_empty_command(self):
        assert AtomicService._handle_multiline_commands('', 'sh') == ''
        assert AtomicService._handle_multiline_commands('', 'cmd') == ''

    def test_handle_multiline_command_cmd_comments(self):
        commands = '\n'.join([
            'command1',
            'REM this is a comment',
            ' rem this is another comment',
            'command2',
            ' :: another comment',
            ':: another comment',
            ' @ REM another comment',
            'command3',
            '@rem more comments'
        ])
        want = 'command1 && command2 && command3'
        assert AtomicService._handle_multiline_commands(commands, 'cmd') == want

    def test_handle_multiline_command_shell_comments(self):
        commands = '\n'.join([
            'command1',
            '# comment',
            ' # comment',
            'command2',
            ';# comment',
            '; # comment',
            'echo thisis#notacomment',
            'echo thisis;#a comment',
            'command3 # trailing comment',
            'command4;#trailing comment',
            'command5; #trailing comment',
            'echo "this is # not a comment" # but this is',
            'echo "\'" can you \'"\' handle "complex # quotes" # but still find the comment; #? ##',
        ])
        want = 'command1; command2; echo thisis#notacomment; echo thisis; command3; command4; command5; ' \
            'echo "this is # not a comment"; echo "\'" can you \'"\' handle "complex # quotes"'
        assert AtomicService._handle_multiline_commands(commands, 'sh') == want

    def test_handle_multiline_command_powershell_comments(self):
        commands = '\n'.join([
            'command1',
            '# comment',
            ' # comment',
            'command2',
            ';# comment',
            '; # comment',
            'echo thisis#notacomment',
            'echo thisis;#a comment',
            'command3 # trailing comment',
            'command4;#trailing comment',
            'command5; #trailing comment',
            'echo "this is # not a comment" # but this is',
            'echo "\'" can you \'"\' han`"dle "complex # quotes" # but still find the comment; #? ##',
            'echo `"this is not actually a quote # so this comment should be removed `"',
        ])
        want = 'command1; command2; echo thisis#notacomment; echo thisis; command3; command4; command5; ' \
               'echo "this is # not a comment"; echo "\'" can you \'"\' han`"dle "complex # quotes"; ' \
               'echo `"this is not actually a quote'
        assert AtomicService._handle_multiline_commands(commands, 'psh') == want

    def test_handle_multiline_command_shell_semicolon(self):
        commands = '\n'.join([
            'command1',
            '# comment',
            ' # comment',
            'command2; ',
            'command3 ;',
            'command4;;',
            'command5'
        ])
        want = 'command1; command2; command3 ; command4;; command5'
        assert AtomicService._handle_multiline_commands(commands, 'sh') == want

    def test_handle_multiline_command_shell_loop(self):
        commands = '\n'.join([
            'for port in {1..65535};',
            '# comment',
            ' # comment',
            'do ',
            'innerloopcommand;',
            'innerloopcommand2',
            'done'
        ])
        want = 'for port in {1..65535}; do innerloopcommand; innerloopcommand2; done'
        assert AtomicService._handle_multiline_commands(commands, 'sh') == want

    def test_handle_multiline_command_shell_ifthen(self):
        commands = '\n'.join([
            'if condition; then',
            '# comment',
            ' # comment',
            'innercommand;',
            'innercommand2;',
            'fi'
        ])
        want = 'if condition; then innercommand; innercommand2; fi'
        assert AtomicService._handle_multiline_commands(commands, 'sh') == want

    def test_handle_multiline_command_no_extra_semicolon_after_fi(self):
        """Regression test for issue #3097: whitespace-only lines between prereq block
        (ending with 'fi;') and the ability command must not produce a stray '; ' separator,
        which resulted in commands like 'fi;  ;  ip neighbour show'."""
        # Simulate the precmd built by _prepare_executor:
        # dep_construct ends with 'fi;', then '  \n  ' (two spaces) separates it from the
        # ability command — matching the double-space pattern of the actual bug report.
        commands = 'if [ -x "$(command -v ip)" ]; then : ; else apt-get install iproute2 -y; fi;\n  \n  ip neighbour show'
        result = AtomicService._handle_multiline_commands(commands, 'sh')
        assert not re.search(r';\s+;', result), \
            f"Unexpected consecutive semicolons with only whitespace between them in: {result!r}"
        assert 'ip neighbour show' in result

    def test_whitespace_only_lines(self):
        commands = '\n'.join(['cmd1', '   ', 'cmd2'])
        result = AtomicService._handle_multiline_commands(commands, 'sh')
        assert 'cmd1' in result
        assert 'cmd2' in result


# ============================================================================
# Concatenate shell commands
# ============================================================================

class TestConcatenateShellCommands:
    def test_empty_list(self):
        assert AtomicService._concatenate_shell_commands([]) == ''

    def test_single_command(self):
        assert AtomicService._concatenate_shell_commands(['echo hello']) == 'echo hello'

    def test_multiple_commands(self):
        result = AtomicService._concatenate_shell_commands(['cmd1', 'cmd2', 'cmd3'])
        assert result == 'cmd1; cmd2; cmd3'

    def test_line_ending_with_do(self):
        result = AtomicService._concatenate_shell_commands(['for i in x; do', 'echo $i', 'done'])
        assert result == 'for i in x; do echo $i; done'

    def test_line_ending_with_then(self):
        result = AtomicService._concatenate_shell_commands(['if true; then', 'echo yes', 'fi'])
        assert result == 'if true; then echo yes; fi'

    def test_line_ending_with_semicolon(self):
        result = AtomicService._concatenate_shell_commands(['cmd1;', 'cmd2'])
        assert result == 'cmd1; cmd2'

    def test_last_line_no_trailing_semicolon(self):
        result = AtomicService._concatenate_shell_commands(['cmd1', 'cmd2'])
        assert not result.endswith('; ')


# ============================================================================
# Remove DOS comment lines
# ============================================================================

class TestRemoveDosCommentLines:
    def test_remove_rem_comment(self):
        lines = ['command1', 'REM comment', 'command2']
        result = AtomicService._remove_dos_comment_lines(lines)
        assert result == ['command1', 'command2']

    def test_remove_lowercase_rem(self):
        lines = ['rem comment', 'command']
        result = AtomicService._remove_dos_comment_lines(lines)
        assert result == ['command']

    def test_remove_double_colon_comment(self):
        lines = [':: comment', 'command']
        result = AtomicService._remove_dos_comment_lines(lines)
        assert result == ['command']

    def test_remove_at_rem(self):
        lines = ['@rem comment', 'command']
        result = AtomicService._remove_dos_comment_lines(lines)
        assert result == ['command']

    def test_keep_non_comments(self):
        lines = ['echo hello', 'dir']
        result = AtomicService._remove_dos_comment_lines(lines)
        assert result == lines

    def test_empty_list(self):
        assert AtomicService._remove_dos_comment_lines([]) == []


# ============================================================================
# Remove shell comments
# ============================================================================

class TestRemoveShellComments:
    def test_remove_line_comment(self):
        lines = ['# this is a comment', 'echo hello']
        result = AtomicService._remove_shell_comments(lines, 'sh')
        assert result == ['echo hello']

    def test_remove_trailing_comment(self):
        lines = ['echo hello # comment']
        result = AtomicService._remove_shell_comments(lines, 'sh')
        assert result == ['echo hello']

    def test_preserve_hash_in_quotes(self):
        lines = ['echo "this # is not a comment"']
        result = AtomicService._remove_shell_comments(lines, 'sh')
        assert result == ['echo "this # is not a comment"']

    def test_psh_escaped_quotes(self):
        lines = ['echo `"not a real quote # comment `"']
        result = AtomicService._remove_shell_comments(lines, 'psh')
        assert result == ['echo `"not a real quote']

    def test_sh_escaped_quotes(self):
        lines = ["echo \\'not a real quote # comment \\'"]
        result = AtomicService._remove_shell_comments(lines, 'sh')
        # The escaped quotes should be removed during processing, leaving the # as a comment
        assert len(result) == 1

    def test_semicolon_comment(self):
        lines = ['echo hello;# comment']
        result = AtomicService._remove_shell_comments(lines, 'sh')
        assert result == ['echo hello']

    def test_empty_lines(self):
        assert AtomicService._remove_shell_comments([], 'sh') == []


# ============================================================================
# Default inputs
# ============================================================================

class TestUseDefaultInputs:
    def test_use_default_inputs(self, atomic_svc, atomic_test):
        platform = 'windows'
        string_to_analyze = '#{recon_commands} -a'
        test = atomic_test
        test['input_arguments']['recon_commands']['default'] = \
            'PathToAtomicsFolder\\T1016\\src\\nonexistent-qakbot.bat'
        got = atomic_svc._use_default_inputs(test=test,
                                             platform=platform,
                                             string_to_analyse=string_to_analyze)
        assert got[0] == 'PathToAtomicsFolder\\T1016\\src\\nonexistent-qakbot.bat -a'
        assert got[1] == []

    def test_use_default_inputs_empty_string(self, atomic_svc, atomic_test):
        platform = 'windows'
        string_to_analyze = ''
        got = atomic_svc._use_default_inputs(test=atomic_test,
                                             platform=platform,
                                             string_to_analyse=string_to_analyze)
        assert got[0] == ''
        assert got[1] == []

    def test_use_default_inputs_nil_valued(self, atomic_svc, atomic_test):
        platform = 'windows'
        string_to_analyze = '#{recon_commands}'
        test = atomic_test
        test['input_arguments']['recon_commands']['default'] = ''
        got = atomic_svc._use_default_inputs(test=test,
                                             platform=platform,
                                             string_to_analyse=string_to_analyze)
        assert got[0] == ''
        assert got[1] == []

    def test_use_default_inputs_multiple_variables(self, atomic_svc):
        test = {
            'input_arguments': {
                'var_a': {'default': 'ALPHA'},
                'var_b': {'default': 'BETA'},
            },
            'executor': {'command': '#{var_a} #{var_b}', 'name': 'sh'}
        }
        got = atomic_svc._use_default_inputs(test=test, platform='linux',
                                             string_to_analyse='#{var_a} and #{var_b}')
        assert got[0] == 'ALPHA and BETA'

    def test_use_default_inputs_no_variables(self, atomic_svc, atomic_test):
        got = atomic_svc._use_default_inputs(test=atomic_test, platform='linux',
                                             string_to_analyse='plain command')
        assert got[0] == 'plain command'
        assert got[1] == []

    def test_use_default_inputs_reserved_parameter(self, atomic_svc, atomic_test):
        """Commands with reserved parameters (#{server}, #{paw}, etc.) should be left untouched."""
        got = atomic_svc._use_default_inputs(test=atomic_test, platform='linux',
                                             string_to_analyse='curl #{server}/file')
        assert got[0] == 'curl #{server}/file'

    def test_use_default_inputs_integer_default(self, atomic_svc):
        """Default value that is an integer should be converted to string."""
        test = {
            'input_arguments': {
                'port': {'default': 8080},
            },
            'executor': {'command': 'nc -l #{port}', 'name': 'sh'}
        }
        got = atomic_svc._use_default_inputs(test=test, platform='linux',
                                             string_to_analyse='nc -l #{port}')
        assert got[0] == 'nc -l 8080'


# ============================================================================
# has_reserved_parameter
# ============================================================================

class TestHasReservedParameter:
    def test_has_server(self, atomic_svc):
        assert atomic_svc._has_reserved_parameter('#{server}/api')

    def test_has_paw(self, atomic_svc):
        assert atomic_svc._has_reserved_parameter('agent #{paw}')

    def test_has_group(self, atomic_svc):
        assert atomic_svc._has_reserved_parameter('#{group}')

    def test_has_location(self, atomic_svc):
        assert atomic_svc._has_reserved_parameter('#{location}/file')

    def test_no_reserved(self, atomic_svc):
        assert not atomic_svc._has_reserved_parameter('echo hello')

    def test_custom_variable_not_reserved(self, atomic_svc):
        assert not atomic_svc._has_reserved_parameter('#{custom_var}')


# ============================================================================
# catch_path_to_atomics_folder
# ============================================================================

class TestCatchPathToAtomicsFolder:
    def test_no_path_in_string(self, atomic_svc):
        result, payloads = atomic_svc._catch_path_to_atomics_folder('no path here', 'linux')
        assert result == 'no path here'
        assert payloads == []

    def test_path_with_nonexistent_file(self, atomic_svc):
        cmd = '$PathToAtomicsFolder/T1234/src/nonexistent.sh'
        result, payloads = atomic_svc._catch_path_to_atomics_folder(cmd, 'linux')
        # Since the file doesn't exist, it should remain unchanged
        assert result == cmd
        assert payloads == []

    def test_path_with_backslash_windows(self, atomic_svc):
        cmd = 'PathToAtomicsFolder\\T1234\\src\\nonexistent.bat'
        result, payloads = atomic_svc._catch_path_to_atomics_folder(cmd, 'windows')
        # File doesn't exist, so no replacement
        assert payloads == []


# ============================================================================
# gen_single_match_tactic_technique (generator)
# ============================================================================

class TestGenSingleMatchTacticTechnique:
    def test_basic_match(self, mitre_json_data):
        results = list(AtomicService._gen_single_match_tactic_technique(mitre_json_data))
        # T1016 -> discovery, T1059 -> execution + persistence
        assert ('discovery', 'T1016') in results
        assert ('execution', 'T1059') in results
        assert ('persistence', 'T1059') in results

    def test_skips_non_attack_patterns(self, mitre_json_data):
        results = list(AtomicService._gen_single_match_tactic_technique(mitre_json_data))
        # S0001 is malware type, should not appear
        assert all(ext_id != 'S0001' for _, ext_id in results)

    def test_skips_non_mitre_sources(self, mitre_json_data):
        results = list(AtomicService._gen_single_match_tactic_technique(mitre_json_data))
        assert all(ext_id != 'X9999' for _, ext_id in results)

    def test_empty_json(self):
        results = list(AtomicService._gen_single_match_tactic_technique({}))
        assert results == []

    def test_empty_objects(self):
        results = list(AtomicService._gen_single_match_tactic_technique({'objects': []}))
        assert results == []

    def test_object_without_external_references(self):
        data = {'objects': [{'type': 'attack-pattern'}]}
        results = list(AtomicService._gen_single_match_tactic_technique(data))
        assert results == []

    def test_object_without_kill_chain_phases(self):
        data = {'objects': [{
            'type': 'attack-pattern',
            'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T0001'}]
        }]}
        results = list(AtomicService._gen_single_match_tactic_technique(data))
        assert results == []


# ============================================================================
# populate_dict_techniques_tactics
# ============================================================================

class TestPopulateDictTechniquesTactics:
    @pytest.mark.asyncio
    async def test_populates_mapping(self, atomic_svc, mitre_json_data):
        mock_file = mock_open(read_data=json.dumps(mitre_json_data))
        with patch('builtins.open', mock_file):
            await atomic_svc._populate_dict_techniques_tactics()

        assert 'T1016' in atomic_svc.technique_to_tactics
        assert 'discovery' in atomic_svc.technique_to_tactics['T1016']
        assert 'T1059' in atomic_svc.technique_to_tactics
        assert 'execution' in atomic_svc.technique_to_tactics['T1059']
        assert 'persistence' in atomic_svc.technique_to_tactics['T1059']


# ============================================================================
# clone_atomic_red_team_repo
# ============================================================================

class TestCloneAtomicRedTeamRepo:
    @pytest.mark.asyncio
    async def test_clone_default_url(self, atomic_svc):
        with patch('os.path.exists', return_value=False), \
             patch('app.atomic_svc.check_call') as mock_call:
            await atomic_svc.clone_atomic_red_team_repo()
            mock_call.assert_called_once()
            args = mock_call.call_args[0][0]
            assert 'https://github.com/redcanaryco/atomic-red-team.git' in args

    @pytest.mark.asyncio
    async def test_clone_custom_url(self, atomic_svc):
        with patch('os.path.exists', return_value=False), \
             patch('app.atomic_svc.check_call') as mock_call:
            await atomic_svc.clone_atomic_red_team_repo(repo_url='https://example.com/fork.git')
            args = mock_call.call_args[0][0]
            assert 'https://example.com/fork.git' in args

    @pytest.mark.asyncio
    async def test_clone_skips_when_exists(self, atomic_svc):
        with patch('os.path.exists', return_value=True), \
             patch('os.listdir', return_value=['some_file']), \
             patch('app.atomic_svc.check_call') as mock_call:
            await atomic_svc.clone_atomic_red_team_repo()
            mock_call.assert_not_called()

    @pytest.mark.asyncio
    async def test_clone_runs_when_dir_empty(self, atomic_svc):
        with patch('os.path.exists', return_value=True), \
             patch('os.listdir', return_value=[]), \
             patch('app.atomic_svc.check_call') as mock_call:
            await atomic_svc.clone_atomic_red_team_repo()
            mock_call.assert_called_once()


# ============================================================================
# prepare_cmd
# ============================================================================

class TestPrepareCmd:
    @pytest.mark.asyncio
    async def test_basic_prepare(self, atomic_svc, atomic_test_linux):
        cmd, payloads = await atomic_svc._prepare_cmd(
            atomic_test_linux, 'linux', 'sh',
            'whoami > #{output_file}'
        )
        assert '/tmp/output.txt' in cmd
        assert payloads == []

    @pytest.mark.asyncio
    async def test_multiline_prepare(self, atomic_svc, atomic_test_linux):
        cmd, payloads = await atomic_svc._prepare_cmd(
            atomic_test_linux, 'linux', 'sh',
            'line1\nline2\nline3'
        )
        assert '; ' in cmd or cmd == 'line1; line2; line3'

    @pytest.mark.asyncio
    async def test_empty_command(self, atomic_svc, atomic_test_linux):
        cmd, payloads = await atomic_svc._prepare_cmd(
            atomic_test_linux, 'linux', 'sh', ''
        )
        assert cmd == ''
        assert payloads == []


# ============================================================================
# prepare_executor
# ============================================================================

class TestPrepareExecutor:
    @pytest.mark.asyncio
    async def test_basic_executor(self, atomic_svc, atomic_test_linux):
        command, cleanup, payloads = await atomic_svc._prepare_executor(
            atomic_test_linux, 'linux', 'sh'
        )
        assert 'whoami' in command
        assert payloads == []

    @pytest.mark.asyncio
    async def test_executor_with_cleanup(self, atomic_svc):
        test = {
            'name': 'test',
            'input_arguments': {},
            'executor': {
                'command': 'mkdir /tmp/test_dir',
                'cleanup_command': 'rm -rf /tmp/test_dir',
                'name': 'sh'
            }
        }
        command, cleanup, payloads = await atomic_svc._prepare_executor(test, 'linux', 'sh')
        assert 'mkdir' in command
        assert 'rm -rf' in cleanup

    @pytest.mark.asyncio
    async def test_executor_no_cleanup(self, atomic_svc, atomic_test_linux):
        command, cleanup, payloads = await atomic_svc._prepare_executor(
            atomic_test_linux, 'linux', 'sh'
        )
        assert cleanup == ''

    @pytest.mark.asyncio
    async def test_executor_with_dependencies_extraction_error(self, atomic_svc):
        """Dependencies that can't be automated should be skipped gracefully."""
        test = {
            'name': 'test_with_dep',
            'input_arguments': {},
            'dependencies': [
                {
                    'prereq_command': 'echo "Run this manually"; exit 1',
                    'get_prereq_command': 'echo "Sorry, cannot automate"',
                }
            ],
            'executor': {
                'command': 'echo hello',
                'name': 'sh'
            }
        }
        command, cleanup, payloads = await atomic_svc._prepare_executor(test, 'linux', 'sh')
        # Even though the prereq fails, we still get the command
        assert 'echo hello' in command


# ============================================================================
# save_ability
# ============================================================================

class TestSaveAbility:
    @pytest.mark.asyncio
    async def test_save_ability_creates_file(self, atomic_svc, atomic_entries, tmp_path):
        atomic_svc.data_dir = str(tmp_path / 'data')
        atomic_svc.payloads_dir = str(tmp_path / 'payloads')
        os.makedirs(atomic_svc.payloads_dir, exist_ok=True)
        atomic_svc.technique_to_tactics = defaultdict(list, {'T1016': ['discovery']})
        atomic_svc.repo_dir = str(tmp_path / 'repo')

        test = {
            'name': 'Test Ability',
            'description': 'A test',
            'supported_platforms': ['linux'],
            'input_arguments': {},
            'executor': {
                'command': 'whoami',
                'name': 'sh'
            }
        }
        result = await atomic_svc._save_ability(atomic_entries, test)
        assert result is True
        ability_dir = os.path.join(atomic_svc.data_dir, 'abilities', 'discovery')
        assert os.path.isdir(ability_dir)
        files = os.listdir(ability_dir)
        assert len(files) == 1
        assert files[0].endswith('.yml')

    @pytest.mark.asyncio
    async def test_save_ability_manual_skipped(self, atomic_svc, atomic_entries, atomic_test_manual):
        atomic_svc.technique_to_tactics = defaultdict(list, {'T1016': ['discovery']})
        result = await atomic_svc._save_ability(atomic_entries, atomic_test_manual)
        assert result is False

    @pytest.mark.asyncio
    async def test_save_ability_multiple_tactics(self, atomic_svc, atomic_entries, tmp_path):
        atomic_svc.data_dir = str(tmp_path / 'data')
        atomic_svc.payloads_dir = str(tmp_path / 'payloads')
        os.makedirs(atomic_svc.payloads_dir, exist_ok=True)
        atomic_svc.technique_to_tactics = defaultdict(list, {
            'T1016': ['discovery', 'collection']
        })
        atomic_svc.repo_dir = str(tmp_path / 'repo')

        test = {
            'name': 'Multi-tactic Test',
            'description': 'A test with multiple tactics',
            'supported_platforms': ['linux'],
            'input_arguments': {},
            'executor': {
                'command': 'whoami',
                'name': 'sh'
            }
        }
        result = await atomic_svc._save_ability(atomic_entries, test)
        assert result is True
        ability_dir = os.path.join(atomic_svc.data_dir, 'abilities', 'multiple')
        assert os.path.isdir(ability_dir)

    @pytest.mark.asyncio
    async def test_save_ability_unknown_technique(self, atomic_svc, tmp_path):
        atomic_svc.data_dir = str(tmp_path / 'data')
        atomic_svc.payloads_dir = str(tmp_path / 'payloads')
        os.makedirs(atomic_svc.payloads_dir, exist_ok=True)
        atomic_svc.technique_to_tactics = defaultdict(list)
        atomic_svc.repo_dir = str(tmp_path / 'repo')

        entries = {'attack_technique': 'T9999', 'display_name': 'Unknown'}
        test = {
            'name': 'Unknown Tech',
            'description': 'Test for unknown technique',
            'supported_platforms': ['linux'],
            'input_arguments': {},
            'executor': {
                'command': 'echo test',
                'name': 'sh'
            }
        }
        result = await atomic_svc._save_ability(entries, test)
        assert result is True
        ability_dir = os.path.join(atomic_svc.data_dir, 'abilities', 'redcanary-unknown')
        assert os.path.isdir(ability_dir)

    @pytest.mark.asyncio
    async def test_save_ability_psh_has_parsers(self, atomic_svc, atomic_entries, tmp_path):
        atomic_svc.data_dir = str(tmp_path / 'data')
        atomic_svc.payloads_dir = str(tmp_path / 'payloads')
        os.makedirs(atomic_svc.payloads_dir, exist_ok=True)
        atomic_svc.technique_to_tactics = defaultdict(list, {'T1016': ['discovery']})
        atomic_svc.repo_dir = str(tmp_path / 'repo')

        test = {
            'name': 'PSH Test',
            'description': 'PowerShell test',
            'supported_platforms': ['windows'],
            'input_arguments': {},
            'executor': {
                'command': 'Get-Process',
                'name': 'powershell'
            }
        }
        result = await atomic_svc._save_ability(atomic_entries, test)
        assert result is True

        import yaml
        ability_dir = os.path.join(atomic_svc.data_dir, 'abilities', 'discovery')
        files = os.listdir(ability_dir)
        with open(os.path.join(ability_dir, files[0]), 'r') as f:
            data = yaml.safe_load(f)
        assert 'parsers' in data[0]['platforms']['windows']['psh']


# ============================================================================
# populate_data_directory
# ============================================================================

class TestPopulateDataDirectory:
    @pytest.mark.asyncio
    async def test_populate_calls_techniques_if_empty(self, atomic_svc):
        with patch.object(atomic_svc, '_populate_dict_techniques_tactics', new_callable=AsyncMock) as mock_pop, \
             patch('glob.iglob', return_value=[]):
            await atomic_svc.populate_data_directory()
            mock_pop.assert_called_once()

    @pytest.mark.asyncio
    async def test_populate_skips_techniques_if_filled(self, atomic_svc):
        atomic_svc.technique_to_tactics = {'T1016': ['discovery']}
        with patch.object(atomic_svc, '_populate_dict_techniques_tactics', new_callable=AsyncMock) as mock_pop, \
             patch('glob.iglob', return_value=[]):
            await atomic_svc.populate_data_directory()
            mock_pop.assert_not_called()


# ============================================================================
# prereq_formater
# ============================================================================

class TestPrereqFormater:
    @pytest.mark.asyncio
    async def test_sh_falsy_prereq(self, atomic_svc):
        result = await atomic_svc._prereq_formater(
            prereq_test='if test -f /file; exit 1',
            prereq='wget http://example.com/file',
            prereq_type='sh',
            exec_type='sh',
            ability_command='echo done'
        )
        assert 'wget' in result
        assert 'echo done' in result

    @pytest.mark.asyncio
    async def test_sh_truthy_prereq(self, atomic_svc):
        result = await atomic_svc._prereq_formater(
            prereq_test='if test -f /file; exit 0',
            prereq='wget http://example.com/file',
            prereq_type='sh',
            exec_type='sh',
            ability_command='echo done'
        )
        assert 'else' in result

    @pytest.mark.asyncio
    async def test_psh_try_prereq(self, atomic_svc):
        result = await atomic_svc._prereq_formater(
            prereq_test='Try { Get-Item file } Catch { exit 1 }',
            prereq='Install-Module thing',
            prereq_type='psh',
            exec_type='psh',
            ability_command='Use-Module thing'
        )
        assert 'Install-Module' in result

    @pytest.mark.asyncio
    async def test_psh_falsy_prereq(self, atomic_svc):
        result = await atomic_svc._prereq_formater(
            prereq_test='if (Test-Path file) { exit 1 }',
            prereq='Download-File file',
            prereq_type='psh',
            exec_type='psh',
            ability_command='Use-File file'
        )
        assert 'Download-File' in result

    @pytest.mark.asyncio
    async def test_cmd_falsy_prereq(self, atomic_svc):
        result = await atomic_svc._prereq_formater(
            prereq_test='IF EXIST file (exit 1) ELSE (exit 0)',
            prereq='curl http://example.com/file',
            prereq_type='cmd',
            exec_type='cmd',
            ability_command='run_file'
        )
        assert 'curl' in result

    @pytest.mark.asyncio
    async def test_cmd_truthy_prereq(self, atomic_svc):
        result = await atomic_svc._prereq_formater(
            prereq_test='IF EXIST file (exit 0) ELSE (exit 1)',
            prereq='curl http://example.com/file',
            prereq_type='cmd',
            exec_type='cmd',
            ability_command='run_file'
        )
        assert 'call' in result  # truthy uses 'call'

    @pytest.mark.asyncio
    async def test_raises_on_echo_prereq(self, atomic_svc):
        with pytest.raises(ExtractionError):
            await atomic_svc._prereq_formater(
                prereq_test='echo "check manually"',
                prereq='echo "Run this manually"',
                prereq_type='sh',
                exec_type='sh',
                ability_command='cmd'
            )

    @pytest.mark.asyncio
    async def test_raises_on_sorry_prereq(self, atomic_svc):
        with pytest.raises(ExtractionError):
            await atomic_svc._prereq_formater(
                prereq_test='echo check',
                prereq='echo Sorry, cannot automate',
                prereq_type='sh',
                exec_type='sh',
                ability_command='cmd'
            )

    @pytest.mark.asyncio
    async def test_unknown_prereq_type_returns_ability(self, atomic_svc):
        result = await atomic_svc._prereq_formater(
            prereq_test='if test; exit 1',
            prereq='install_thing',
            prereq_type='unknown',
            exec_type='sh',
            ability_command='my_command'
        )
        assert result == 'my_command'

    @pytest.mark.asyncio
    async def test_cross_type_cmd_psh(self, atomic_svc):
        result = await atomic_svc._prereq_formater(
            prereq_test='IF EXIST file (exit 1) ELSE (exit 0)',
            prereq='curl file',
            prereq_type='cmd',
            exec_type='psh',
            ability_command='Use-File'
        )
        assert 'Use-File' in result

    @pytest.mark.asyncio
    async def test_cross_type_psh_cmd(self, atomic_svc):
        result = await atomic_svc._prereq_formater(
            prereq_test='if (Test-Path file) { exit 1 }',
            prereq='Download file',
            prereq_type='psh',
            exec_type='cmd',
            ability_command='run_file'
        )
        assert 'powershell -command' in result
