import hashlib
import os
import pytest

from plugins.atomic.app.atomic_svc import AtomicService

DUMMY_PAYLOAD_PATH = '/tmp/dummyatomicpayload'
DUMMY_PAYLOAD_CONTENT = 'Dummy payload content.'
PREFIX_HASH_LENGTH = 6


@pytest.fixture
def atomic_svc():
    return AtomicService()


@pytest.fixture
def generate_dummy_payload():
    with open(DUMMY_PAYLOAD_PATH, 'w') as f:
            f.write(DUMMY_PAYLOAD_CONTENT)
    yield DUMMY_PAYLOAD_PATH
    os.remove(DUMMY_PAYLOAD_PATH)


@pytest.fixture
def multiline_command():
    return '\n'.join([
        'command1',
        'command2',
        'command3',
    ])


class TestAtomicSvc:
    def test_svc_config(self, atomic_svc):
        assert atomic_svc.repo_dir == 'plugins/atomic/data/atomic-red-team'
        assert atomic_svc.data_dir == 'plugins/atomic/data'
        assert atomic_svc.payloads_dir == 'plugins/atomic/payloads'

    def test_normalize_windows_path(self):
        assert AtomicService._normalize_path('windows\\test\\path', 'windows') == 'windows/test/path'

    def test_normalize_posix_path(self):
        assert AtomicService._normalize_path('linux/test/path', 'linux') == 'linux/test/path'

    def test_handle_attachment(self, atomic_svc, generate_dummy_payload):
        target_hash = hashlib.md5(DUMMY_PAYLOAD_CONTENT.encode()).hexdigest()
        target_name = target_hash[:PREFIX_HASH_LENGTH] + '_dummyatomicpayload'
        target_path = atomic_svc.payloads_dir + '/' + target_name
        assert atomic_svc._handle_attachment(DUMMY_PAYLOAD_PATH) == target_name
        assert os.path.isfile(target_path)
        with open(target_path, 'r') as f:
            file_data = f.read()
        assert file_data == DUMMY_PAYLOAD_CONTENT

    def test_handle_multiline_command_sh(self, multiline_command):
        target = 'command1; command2; command3'
        assert AtomicService._handle_multiline_commands(multiline_command, 'sh') == target

    def test_handle_multiline_command_cmd(self, multiline_command):
        target = 'command1 && command2 && command3'
        assert AtomicService._handle_multiline_commands(multiline_command, 'cmd') == target
