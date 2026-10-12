import ast
import unittest
from pathlib import Path


class ProbeProgramTests(unittest.TestCase):
    def test_constant_subprocess_programs_compile(self):
        # Module compilation cannot catch syntax errors in nested Python -c text.
        found = 0
        for path in Path("scripts").glob("probe_*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.List):
                    continue
                for index, element in enumerate(node.elts):
                    if (
                        not isinstance(element, ast.Constant)
                        or element.value != "-c"
                        or index == 0
                        or index + 1 >= len(node.elts)
                    ):
                        continue
                    executable = node.elts[index - 1]
                    if not isinstance(executable, ast.Constant) or executable.value not in {
                        "python3",
                        "/usr/bin/python3",
                    }:
                        continue
                    program = node.elts[index + 1]
                    if isinstance(program, ast.Constant) and isinstance(program.value, str):
                        with self.subTest(path=path, line=program.lineno):
                            compile(program.value, "<probe subprocess>", "exec")
                        found += 1
        self.assertGreater(found, 0)
