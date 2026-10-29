import sys
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agy_golden_stack.ub_mode_guard import UBModeGuard, _is_production_file

def test_is_production_file_edge_cases():
    # Production files (starts with src/ or has src in parts)
    assert _is_production_file("src/main.py") is True
    assert _is_production_file("src/tests_folder/main.py") is True # 'tests_folder' is not 'tests'
    assert _is_production_file("./src/main.py") is True
    assert _is_production_file("src\\main.py") is True # backslashes are replaced
    assert _is_production_file("my_module/src/main.py") is True
    assert _is_production_file("SRC/main.py") is True
    
    # Non-production files (tests, test, etc.)
    assert _is_production_file("tests/test_main.py") is False
    assert _is_production_file("Tests/test_main.py") is False
    assert _is_production_file("TESTS/test_main.py") is False
    assert _is_production_file("test/test_main.py") is False # does not have src/ or tests, returns False
    assert _is_production_file("TEST/test_main.py") is False
    assert _is_production_file("src/tests/test_main.py") is False # 'tests' in parts, takes precedence

def test_verify_tdd_sequence():
    guard = UBModeGuard()
    
    # Compliant: prod file modified with tests
    res = guard.verify_tdd_sequence(["src/main.py"], ["tests/test_main.py"])
    assert res.is_compliant is True
    
    # Compliant: no prod files modified (only non-prod files)
    res = guard.verify_tdd_sequence(["README.md", "tests/test_main.py", "test/file.py", "Tests/test_main.py"], [])
    assert res.is_compliant is True
    
    # Boundary: empty list of modified files
    res = guard.verify_tdd_sequence([], [])
    assert res.is_compliant is True

    # Boundary: whitespace padding in test files
    res = guard.verify_tdd_sequence(["src/main.py"], ["   \t "])
    assert res.is_compliant is False # only whitespace in test_files -> has_tests=False

    res = guard.verify_tdd_sequence(["src/main.py"], ["   tests.py  "])
    assert res.is_compliant is True
    
    # Non-compliant: prod files modified without tests
    res = guard.verify_tdd_sequence(["src/main.py", "src/tests_folder/file.py"], [])
    assert res.is_compliant is False
    assert res.rule_name == "TDD_TEST_FIRST"
    assert "TDD Rule 1 violation" in res.violations[0]
    assert "src/main.py" in res.violations[0]
    assert "src/tests_folder/file.py" in res.violations[0]

def test_check_duplicate_abstractions():
    guard = UBModeGuard()
    
    # 1. Syntax Error
    res = guard.check_duplicate_abstractions("def this is invalid")
    assert res.is_compliant is False
    assert res.rule_name == "NO_DUPLICATION"
    assert "Syntax error parsing source code" in res.violations[0]
    
    # 2. Valid Code, no duplicates
    code = "class A:\n  def f(self): return 1\nclass B:\n  def g(self): return 2"
    res = guard.check_duplicate_abstractions(code)
    assert res.is_compliant is True
    
    # 3. Duplicate parallel classes (same method signatures)
    code = "class ClassA:\n  def do_something(self, a, b): pass\nclass ClassB:\n  def do_something(self, a, b): pass"
    res = guard.check_duplicate_abstractions(code)
    assert res.is_compliant is False
    assert "Duplicate parallel classes detected: 'ClassA' and 'ClassB' share identical method signatures" in res.violations[0]
    
    # 4. Duplicate parallel abstraction (same logic but different method names)
    code = "class ClassA:\n  def method_a(self): return 42\nclass ClassB:\n  def method_b(self): return 42"
    res = guard.check_duplicate_abstractions(code)
    assert res.is_compliant is False
    assert "Duplicate parallel abstraction detected: 'ClassA' and 'ClassB' share identical class logic." in res.violations[0]
    
    # 5. Duplicate helper functions
    code = "def func_a(x): return x * 2\ndef func_b(x): return x * 2"
    res = guard.check_duplicate_abstractions(code)
    assert res.is_compliant is False
    assert "Duplicate helper abstraction detected: functions 'func_a' and 'func_b' share identical implementation logic." in res.violations[0]

def test_evaluate_bus_hook():
    guard = UBModeGuard()
    
    # Missing payload
    res = guard.evaluate_bus_hook({})
    assert res["decision"] == "allow"
    
    # TDD Violation based on payload struct
    res = guard.evaluate_bus_hook({
        "payload": {
            "modified_files": ["src/app.py"],
            "test_files": []
        }
    })
    assert res["decision"] == "block"
    assert "TDD Violation" in res["reason"]
    
    # TDD Violation fallback to target_path
    res = guard.evaluate_bus_hook({
        "payload": {
            "target_path": "src/app.py",
            "test_files": []
        }
    })
    assert res["decision"] == "block"
    
    # TDD Violation fallback to path
    res = guard.evaluate_bus_hook({
        "payload": {
            "path": "src/app.py"
        }
    })
    assert res["decision"] == "block"
    
    # Anti-Decoherence Violation (TDD passes, duplicates found)
    res = guard.evaluate_bus_hook({
        "payload": {
            "modified_files": ["src/app.py"],
            "test_files": ["tests/test_app.py"],
            "source_code": "def func1(): return 1\ndef func2(): return 1"
        }
    })
    assert res["decision"] == "block"
    assert "Anti-Decoherence Violation" in res["reason"]
    
    # Fallback to 'content' for source_code
    res = guard.evaluate_bus_hook({
        "payload": {
            "modified_files": ["src/app.py"],
            "test_files": ["tests/test_app.py"],
            "content": "def func1(): return 1\ndef func2(): return 1"
        }
    })
    assert res["decision"] == "block"
    assert "Anti-Decoherence Violation" in res["reason"]

    # All checks pass
    res = guard.evaluate_bus_hook({
        "payload": {
            "modified_files": ["src/app.py"],
            "test_files": ["tests/test_app.py"],
            "source_code": "def func1(): return 1\ndef func2(): return 2"
        }
    })
    assert res["decision"] == "allow"
    assert "check_result" in res
