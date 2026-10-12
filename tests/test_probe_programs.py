import ast
import unittest
from pathlib import Path


class ProbeProgramTests(unittest.TestCase):
    def test_constant_subprocess_programs_compile(self):
        # Host module compilation cannot catch syntax errors in Python -c text.
        tree = ast.parse(Path("scripts/probe_lab.py").read_text())
        found = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.List):
                continue
            for index, element in enumerate(node.elts[:-1]):
                if not isinstance(element, ast.Constant) or element.value != "-c":
                    continue
                program = node.elts[index + 1]
                if isinstance(program, ast.Constant) and isinstance(program.value, str):
                    with self.subTest(line=program.lineno):
                        compile(program.value, "<probe subprocess>", "exec")
                    found += 1
        self.assertGreater(found, 0)
