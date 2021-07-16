import pytest

from plugins.atomic.app.atomic_svc import AtomicService


@pytest.fixture
def atomic_svc():
    return AtomicService()


class TestAtomicSvc:
    def test_placeholder(self, atomic_svc):
        print(atomic_svc.repo_dir)
        assert True
