import hashlib
import os
import sys
import types
import logging
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from collections import defaultdict

# ---------------------------------------------------------------------------
# Determine paths
# ---------------------------------------------------------------------------
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _repo_root)

# ---------------------------------------------------------------------------
# Stub heavy Caldera imports BEFORE importing any plugin code.
# We create real module objects (not MagicMock) for 'app' so that
# sub-module imports like `from app.atomic_svc import ...` work.
# ---------------------------------------------------------------------------

# Create the 'app' package as a real namespace package
_app_pkg = types.ModuleType('app')
_app_pkg.__path__ = [os.path.join(_repo_root, 'app')]
_app_pkg.__package__ = 'app'
sys.modules['app'] = _app_pkg

# app.utility
_app_utility = types.ModuleType('app.utility')
_app_utility.__path__ = [os.path.join(_repo_root, 'app', 'utility')]
_app_utility.__package__ = 'app.utility'
sys.modules['app.utility'] = _app_utility

# app.objects
_app_objects = types.ModuleType('app.objects')
_app_objects.__path__ = [os.path.join(_repo_root, 'app', 'objects')]
_app_objects.__package__ = 'app.objects'
sys.modules['app.objects'] = _app_objects

# app.service
_app_service = types.ModuleType('app.service')
_app_service.__path__ = [os.path.join(_repo_root, 'app', 'service')]
_app_service.__package__ = 'app.service'
sys.modules['app.service'] = _app_service

# app.parsers
_app_parsers = types.ModuleType('app.parsers')
_app_parsers.__path__ = [os.path.join(_repo_root, 'app', 'parsers')]
_app_parsers.__package__ = 'app.parsers'
sys.modules['app.parsers'] = _app_parsers

# -- app.utility.base_world --
_base_world_mod = types.ModuleType('app.utility.base_world')


class BaseWorld:
    class Access:
        RED = 'red'

    @staticmethod
    def strip_yml(path):
        return []


_base_world_mod.BaseWorld = BaseWorld
sys.modules['app.utility.base_world'] = _base_world_mod

# -- app.utility.base_service --
_base_service_mod = types.ModuleType('app.utility.base_service')


class BaseService:
    @staticmethod
    def add_service(name, svc):
        return logging.getLogger(name)


_base_service_mod.BaseService = BaseService
sys.modules['app.utility.base_service'] = _base_service_mod

# -- app.utility.base_parser --
PARSER_SIGNALS_FAILURE = 'failure'
_base_parser_mod = types.ModuleType('app.utility.base_parser')


class BaseParser:
    def line(self, blob):
        return blob.strip().splitlines()


_base_parser_mod.BaseParser = BaseParser
_base_parser_mod.PARSER_SIGNALS_FAILURE = PARSER_SIGNALS_FAILURE
sys.modules['app.utility.base_parser'] = _base_parser_mod

# -- app.objects.c_agent --
_agent_mod = types.ModuleType('app.objects.c_agent')


class Agent:
    RESERVED = ['#{server}', '#{group}', '#{paw}', '#{location}']


_agent_mod.Agent = Agent
sys.modules['app.objects.c_agent'] = _agent_mod

# -- app.service.auth_svc --
_auth_svc_mod = types.ModuleType('app.service.auth_svc')
_auth_svc_mod.for_all_public_methods = lambda fn: lambda cls: cls
_auth_svc_mod.check_authorization = MagicMock()
sys.modules['app.service.auth_svc'] = _auth_svc_mod

# -- plugin namespace stubs --
_plugins = types.ModuleType('plugins')
_plugins.__path__ = []
sys.modules['plugins'] = _plugins

_plugins_atomic = types.ModuleType('plugins.atomic')
_plugins_atomic.__path__ = [_repo_root]
sys.modules['plugins.atomic'] = _plugins_atomic

_plugins_atomic_app = types.ModuleType('plugins.atomic.app')
_plugins_atomic_app.__path__ = [os.path.join(_repo_root, 'app')]
sys.modules['plugins.atomic.app'] = _plugins_atomic_app

_plugins_atomic_app_parsers = types.ModuleType('plugins.atomic.app.parsers')
_plugins_atomic_app_parsers.__path__ = [os.path.join(_repo_root, 'app', 'parsers')]
sys.modules['plugins.atomic.app.parsers'] = _plugins_atomic_app_parsers

# ---------------------------------------------------------------------------
# Now import the real plugin modules
# ---------------------------------------------------------------------------
from app.atomic_svc import AtomicService  # noqa: E402
from app.atomic_gui import AtomicGUI  # noqa: E402
from app.parsers.atomic_powershell import Parser as AtomicPowershellParser  # noqa: E402

# Register under plugins.atomic namespace too
import app.atomic_svc as _real_atomic_svc
import app.atomic_gui as _real_atomic_gui
import app.parsers.atomic_powershell as _real_atomic_parser

sys.modules['plugins.atomic.app.atomic_svc'] = _real_atomic_svc
sys.modules['plugins.atomic.app.atomic_gui'] = _real_atomic_gui
sys.modules['plugins.atomic.app.parsers.atomic_powershell'] = _real_atomic_parser

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

DUMMY_PAYLOAD_PATH = '/tmp/dummyatomicpayload'
DUMMY_PAYLOAD_CONTENT = 'Dummy payload content.'
PREFIX_HASH_LENGTH = 6


@pytest.fixture
def atomic_svc():
    return AtomicService()


@pytest.fixture
def generate_dummy_payload(tmp_path):
    payload_path = tmp_path / 'dummyatomicpayload'
    payload_path.write_text(DUMMY_PAYLOAD_CONTENT)
    yield str(payload_path)


@pytest.fixture
def multiline_command():
    return '\n'.join([
        'command1',
        'command2',
        'command3',
    ])


@pytest.fixture
def atomic_test():
    return {
        'name': 'Qakbot Recon',
        'auto_generated_guid': '121de5c6-5818-4868-b8a7-8fd07c455c1b',
        'description': 'A list of commands known to be performed by Qakbot',
        'supported_platforms': ['windows'],
        'input_arguments': {
            'recon_commands': {
                'description': 'File that houses commands to be executed',
                'type': 'Path',
                'default': 'PathToAtomicsFolder\\T1016\\src\\qakbot.bat'
            }
        },
        'executor': {
            'command': '#{recon_commands}\n',
            'name': 'command_prompt'
        }
    }


@pytest.fixture
def atomic_test_linux():
    return {
        'name': 'Linux Recon',
        'auto_generated_guid': 'aabbccdd-1111-2222-3333-444455556666',
        'description': 'Linux reconnaissance commands',
        'supported_platforms': ['linux'],
        'input_arguments': {
            'output_file': {
                'description': 'Output file path',
                'type': 'Path',
                'default': '/tmp/output.txt'
            }
        },
        'executor': {
            'command': 'whoami > #{output_file}\nhostname >> #{output_file}\n',
            'name': 'sh'
        }
    }


@pytest.fixture
def atomic_test_manual():
    return {
        'name': 'Manual Test',
        'auto_generated_guid': 'deadbeef-0000-1111-2222-333344445555',
        'description': 'Manual test that should be skipped',
        'supported_platforms': ['windows'],
        'input_arguments': {},
        'executor': {
            'command': 'Do this manually',
            'name': 'manual'
        }
    }


@pytest.fixture
def atomic_entries():
    return {
        'attack_technique': 'T1016',
        'display_name': 'System Network Configuration Discovery'
    }


@pytest.fixture
def mitre_json_data():
    return {
        'objects': [
            {
                'type': 'attack-pattern',
                'external_references': [
                    {'source_name': 'mitre-attack', 'external_id': 'T1016'}
                ],
                'kill_chain_phases': [
                    {'kill_chain_name': 'mitre-attack', 'phase_name': 'discovery'}
                ]
            },
            {
                'type': 'attack-pattern',
                'external_references': [
                    {'source_name': 'mitre-attack', 'external_id': 'T1059'}
                ],
                'kill_chain_phases': [
                    {'kill_chain_name': 'mitre-attack', 'phase_name': 'execution'},
                    {'kill_chain_name': 'mitre-attack', 'phase_name': 'persistence'}
                ]
            },
            {
                'type': 'malware',
                'external_references': [
                    {'source_name': 'mitre-attack', 'external_id': 'S0001'}
                ]
            },
            {
                'type': 'attack-pattern',
                'external_references': [
                    {'source_name': 'other-source', 'external_id': 'X9999'}
                ],
                'kill_chain_phases': [
                    {'kill_chain_name': 'other-chain', 'phase_name': 'other'}
                ]
            }
        ]
    }
