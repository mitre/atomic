import ast
import os

import pytest

yaml = pytest.importorskip("yaml")

PLUGIN_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ATOMIC_SVC_PATH = os.path.join(PLUGIN_DIR, 'app', 'atomic_svc.py')
PAYLOADS_DIR = os.path.join(PLUGIN_DIR, 'payloads')
DATA_DIR = os.path.join(PLUGIN_DIR, 'data')
ATOMICS_DIR = os.path.join(DATA_DIR, 'atomic-red-team', 'atomics')


class TestAtomicSvcMD5Security:
    """Verify that MD5 usage in atomic_svc.py is marked as non-security."""

    @pytest.fixture(autouse=True)
    def _load_source(self):
        with open(ATOMIC_SVC_PATH, 'r', encoding='utf-8') as f:
            self.source = f.read()
        self.tree = ast.parse(self.source)

    def _find_md5_calls(self):
        """Find all hashlib.md5(...) calls and return their AST nodes."""
        md5_calls = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Match hashlib.md5(...)
            if (isinstance(func, ast.Attribute)
                    and func.attr == 'md5'
                    and isinstance(func.value, ast.Name)
                    and func.value.id == 'hashlib'):
                md5_calls.append(node)
        return md5_calls

    def test_md5_calls_exist(self):
        """Verify there are MD5 calls to test."""
        md5_calls = self._find_md5_calls()
        assert len(md5_calls) > 0, (
            "No hashlib.md5() calls found in atomic_svc.py — "
            "test may be outdated"
        )

    def test_md5_calls_use_usedforsecurity_false(self):
        """All hashlib.md5() calls must pass usedforsecurity=False.

        On FIPS-enabled systems, hashlib.md5() raises ValueError unless
        usedforsecurity=False is explicitly set. Since these hashes are
        used for payload naming (not cryptographic security), they should
        be annotated accordingly.
        """
        md5_calls = self._find_md5_calls()
        for call_node in md5_calls:
            keyword_names = [kw.arg for kw in call_node.keywords if kw.arg is not None]
            has_usedforsecurity = 'usedforsecurity' in keyword_names
            if has_usedforsecurity:
                for kw in call_node.keywords:
                    if kw.arg == 'usedforsecurity':
                        assert (
                            isinstance(kw.value, ast.Constant)
                            and kw.value.value is False
                        ), (
                            f"hashlib.md5() at line {call_node.lineno} has "
                            f"usedforsecurity set to a non-False value"
                        )
                        break
            else:
                pytest.fail(
                    f"hashlib.md5() at line {call_node.lineno} in atomic_svc.py "
                    f"is missing usedforsecurity=False — required for FIPS "
                    f"compliance"
                )


class TestAtomicAbilityYAML:
    """Validate that atomic test YAML files are well-formed."""

    def _get_atomic_yaml_files(self):
        """Collect all atomic test YAML files from the data directory."""
        yaml_files = []
        if not os.path.isdir(ATOMICS_DIR):
            return yaml_files
        for technique_dir in os.listdir(ATOMICS_DIR):
            technique_path = os.path.join(ATOMICS_DIR, technique_dir)
            if not os.path.isdir(technique_path):
                continue
            for fname in os.listdir(technique_path):
                if fname.endswith('.yaml') or fname.endswith('.yml'):
                    yaml_files.append(os.path.join(technique_path, fname))
        return sorted(yaml_files)

    def test_yaml_files_exist(self):
        """The atomic data directory should contain YAML test definitions."""
        if not os.path.isdir(ATOMICS_DIR):
            pytest.skip(
                f"Atomics directory not found at {ATOMICS_DIR} — "
                f"run 'git submodule update --init' to populate data"
            )
        yaml_files = self._get_atomic_yaml_files()
        assert len(yaml_files) > 0, (
            f"No YAML files found in {ATOMICS_DIR} — "
            f"run 'git submodule update --init' to populate data"
        )

    def test_yaml_files_are_parseable(self):
        """All YAML files should parse without error."""
        yaml_files = self._get_atomic_yaml_files()
        for fpath in yaml_files:
            with open(fpath, 'r', encoding='utf-8') as f:
                try:
                    data = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    pytest.fail(
                        f"Failed to parse {fpath}: {e}"
                    )
                assert data is not None, (
                    f"YAML file is empty: {fpath}"
                )

    def test_yaml_files_have_required_fields(self):
        """Each atomic YAML should have attack_technique and atomic_tests."""
        yaml_files = self._get_atomic_yaml_files()
        for fpath in yaml_files:
            # Only check technique YAML files (T*.yaml pattern)
            basename = os.path.basename(fpath)
            if not basename.startswith('T'):
                continue
            with open(fpath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            assert 'attack_technique' in data, (
                f"Missing 'attack_technique' in {fpath}"
            )
            assert 'atomic_tests' in data, (
                f"Missing 'atomic_tests' in {fpath}"
            )
            assert isinstance(data['atomic_tests'], list), (
                f"'atomic_tests' should be a list in {fpath}"
            )


class TestPayloadsDirectory:
    """Verify the payloads directory exists for storing atomic payloads."""

    def test_payloads_directory_exists(self):
        """The payloads directory must exist for atomic payload storage."""
        assert os.path.isdir(PAYLOADS_DIR), (
            f"Payloads directory does not exist: {PAYLOADS_DIR}"
        )
