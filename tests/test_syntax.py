from compileall import compile_file
import pytest
from .conftest import SOURCE_DIR


py_files = list(SOURCE_DIR.rglob('*.py'))


@pytest.mark.parametrize(
    'item',
    py_files,
    ids=[item.name for item in py_files])
def test_syntax(item):
    assert compile_file(item)
