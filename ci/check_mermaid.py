"""Extract every ```mermaid block from README.md and docs/**/*.md into .mmd files for mermaid-cli."""

import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
n = 0
for md in [root / "README.md", *sorted((root / "docs").rglob("*.md"))]:
    for i, block in enumerate(re.findall(r"```mermaid\n(.*?)```", md.read_text(encoding="utf-8"), re.S)):
        name = f"{md.relative_to(root).as_posix().replace('/', '_')}_{i}.mmd"
        (out / name).write_text(block, encoding="utf-8")
        n += 1
        print(name)
if not n:
    sys.exit("no mermaid blocks found")
