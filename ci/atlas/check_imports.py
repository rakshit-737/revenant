"""Try every import statement of atlas.py inside the TensorFlow container; report each one."""
import ast
import glob
import sys

path = sorted(glob.glob(sys.argv[1] + "/*/atlas.py"))[0]
lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
failed = 0
for node in ast.walk(ast.parse("\n".join(lines))):
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        stmt = lines[node.lineno - 1].strip()
        try:
            exec(stmt, {})  # noqa: S102  # nosec B102 - import statements of the pinned ATLAS release
            print("ok   ", stmt)
        except Exception as exc:  # noqa: BLE001 - report every failure
            failed += 1
            print("FAIL ", stmt, "->", repr(exc))
print("failed imports:", failed)
