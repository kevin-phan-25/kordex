import importlib.machinery
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
INFRA_TEST = ROOT / "tests/infrastructure/test_postgres_recovery_measurement_contract.py"


class UnittestDiscoveryRegressionTests(unittest.TestCase):
    def test_postgres_contract_module_resolves_from_infrastructure_with_scripts_first(self):
        # Infrastructure tests may prepend scripts/ to sys.path while importing
        # helpers. Confirm the module name still resolves to the intended suite.
        spec = importlib.machinery.PathFinder.find_spec(
            INFRA_TEST.stem,
            [str(ROOT / "scripts"), str(INFRA_TEST.parent)],
        )
        self.assertIsNotNone(spec)
        self.assertEqual(Path(spec.origin).resolve(), INFRA_TEST.resolve())

        code = (
            "import importlib, pathlib, sys, unittest; "
            "scripts, infra, expected = sys.argv[1:]; "
            "sys.path[:0] = [scripts, infra]; "
            f"module = importlib.import_module({INFRA_TEST.stem!r}); "
            "assert pathlib.Path(module.__file__).resolve() == pathlib.Path(expected).resolve(); "
            "suite = unittest.defaultTestLoader.loadTestsFromModule(module); "
            "assert suite.countTestCases() == 3, suite.countTestCases(); "
            "result = unittest.TextTestRunner(verbosity=0).run(suite); "
            "raise SystemExit(not result.wasSuccessful())"
        )
        result = subprocess.run(
            [sys.executable, "-c", code, str(ROOT / "scripts"), str(INFRA_TEST.parent), str(INFRA_TEST)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
