import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
LAB = ROOT / "infrastructure/terraform/gcp/self-managed-lab"


class QualificationProjectGuardTests(unittest.TestCase):
    def test_product_project_is_denied_by_variable_validation(self):
        variables = (LAB / "variables.tf").read_text()
        project_variable = re.search(
            r'variable "project_id"\s*\{(?P<body>.*?)\n\}', variables, re.S
        )
        self.assertIsNotNone(project_variable)
        body = project_variable.group("body")
        self.assertIn('"kordex-fleet-platform"', body)
        self.assertRegex(body, r"!contains\(\[.*?\],\s*var\.project_id\)")

    def test_product_project_has_independent_plan_precondition(self):
        main = (LAB / "main.tf").read_text()
        safety_resource = re.search(
            r'resource "terraform_data" "project_safety"\s*\{(?P<body>.*?)\n\}',
            main,
            re.S,
        )
        self.assertIsNotNone(safety_resource)
        body = safety_resource.group("body")
        self.assertRegex(
            body,
            r"precondition\s*\{\s*condition\s*=\s*var\.project_id\s*!=\s*"
            r'"kordex-fleet-platform"',
        )


if __name__ == "__main__":
    unittest.main()
