# Limitations & roadmap

REVENANT is a research prototype. These are the honest boundaries; several are inherent to
the available public ground truth or need hardware/data that this project deliberately does
not require.

## Limitations

The same list is in the README (both are generated from `docs/snippets/limitations.md`).

--8<-- "docs/snippets/limitations.md"

## Roadmap

--8<-- "docs/snippets/roadmap.md"

## Design stance on AI

The core uses rules and a graph on purpose. Courts distrust black boxes, so explainability is
a design constraint. Every edge names the rule that produced it, and every report line cites
an event id and hash. The only learned part is the per-rule calibration table, fitted from
public ground truth and shipped as readable JSON.
