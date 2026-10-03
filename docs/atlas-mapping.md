# Scoring REVENANT under the ATLAS protocol: entity mapping

ATLAS (Alsaheel et al., USENIX Security 2021) scores attack investigation with
its own `evaluate.py`. Given a list of *predicted attack entities* (field 0 of
an `eval_*.json` file), it marks

* a **graph word** (an entity of ATLAS's causal graph, e.g.
  `c:/users/aalsahee/payload.exe_2064`, `0xalsaheel.com/ripleeszw/ewpsc/`,
  `connection_192.168.223.128_192.168.223.3`) as predicted when any predicted
  string is a **substring** of it, and
* a **log line** (one preprocessed event) as predicted when any predicted string
  is a substring of the line.

The same substring rule against the malicious labels (`malicious_labels.txt`,
e.g. `0xalsaheel.com`, `192.168.223.3`, `payload.exe`, `aalsahee/index.html`)
defines the ground truth. Entity counts are over unique graph words, event
counts over log lines. This page fixes, before any result was seen, how a
REVENANT story becomes such a list. The code is
`revenant.parsers.atlas.entity_labels`; `tests/test_atlas.py` pins every row.

## Inputs REVENANT reads

| ATLAS file | read by REVENANT? |
|---|---|
| test log lines (field 6 of the released `eval_*.json`, identical to `testing_preprocessed_logs_*`) | yes, after `strip_label` removes the `-LA+` / `-LD-` ground-truth suffix of every line |
| symptom entity (field 2; the authors' `atlas.py` sets `user_artifact = malicious_labels[0]`) | yes: the analyst's starting point, as for ATLAS |
| malicious labels (field 1), model words/predictions/probabilities (fields 3-5), hand-cleaned predictions (field 0) | **no**; fields 0, 4 and 5 are overwritten with REVENANT's own output before scoring |

A test parses the fixture with every label flipped (`+` to `-` and back) and
checks that REVENANT produces byte-identical events.

## Records to events

The connector (`revenant.parsers.atlas`) maps ATLAS's 20-field preprocessed
records as follows. Security lines carry no Windows event id, so a process
start is inferred from the first line naming a (pid, image basename) pair.

| record | event |
|---|---|
| Security, first sighting of (pid, image) | `process_start`, parent = `ppid` (image of its latest sighting) |
| Security with an IP endpoint | `network_connect` to the remote end; the host's own address is the IPv4 endpoint seen most often in its log |
| Security, object type `file...` | `file_write` (WriteData/AppendData), else `file_read` (ReadData/Execute), else `file_delete` |
| DNS response | `dns_query` (domain, resolved IP) |
| Firefox HTTP request/response | `web_visit` (URL, host, referer) |

Three cross-entity rules (in the default rule set, but keyed on attributes
only this connector sets) link the new record kinds: `dns_resolved_connect`
(an answer for a name precedes the connection to the address it resolved to),
`dns_web_request` (an answer precedes the web request to that name) and
`web_referer` (a page fetched with a Referer follows the visit to that URL).
The existing `dropped_file_executed` rule links a written file to the process
later started from it.

## Story

* **Seeds**: every event one of whose labels (below) equals the symptom. When the
  symptom is a domain, each address a DNS answer gave for it is an alias and
  events naming an alias are seeds too.
* **Story** (`revenant.stories.seeded_story`): each seed climbs to its story root
  exactly as in REVENANT's normal stories (top-most causal ancestor that is not
  an OS skeleton process); the story keeps every such root's causal subtree,
  capped at 200 events per root with suspicious branches first, omitting benign
  non-process leaves, plus every seed. `revenant_uncapped` removes the cap.

## Story entities to ATLAS strings

Each entity maps to the shortest form that is a substring of both ATLAS's graph
word and its log line for that entity.

| REVENANT entity | ATLAS string | why |
|---|---|---|
| process (`process:pid:image`; for a `process_start` only the started process, never its parent) | lower-case image basename, e.g. `payload.exe` | graph words are `<path without spaces>_<pid>`, lines carry the path with spaces and the pid in another field; the basename is in both, and it is the form the authors' own cleaned lists use |
| file (`file:path`) | lower-case basename, e.g. `secret.docx` | graph words merge paths and drop spaces |
| name containing a space | both spellings, `my secret.docx` and `mysecret.docx` | graph words drop spaces, lines keep them |
| network connection | the remote address, e.g. `192.168.223.3` | the host's own address, loopback, broadcast and multicast are never emitted |
| DNS answer | the domain and the address it resolved to | |
| web request | the URL's host name without port, e.g. `0xalsaheel.com` | covers ATLAS's web-object words `host/path/` |

Strings shorter than 4 characters and the pseudo-process `system` are
dropped (they are substrings of nearly every line). An empty prediction is
written as `<revenant:no-prediction>`, which matches nothing, because
`evaluate.py` stops on an empty list.

## Known biases of the protocol (apply to every method)

* Substring matching over-generalises: predicting `firefox.exe` marks every
  Firefox instance and every line naming it; a label `192.168.223.3` also
  matches `192.168.223.30`.
* ATLAS's released predictions were cleaned by hand before scoring (ATLAS
  README, "manual cleaning"); REVENANT's are produced automatically.
* Multi-host attacks are scored per host with each host's own symptom (the
  first label of that host), in one folder holding both hosts' files, as the
  authors do for ATLAS.

Results: [`results/atlas_revenant.json`](https://github.com/rakshit-737/revenant/blob/main/results/atlas_revenant.json)
and the [Evaluation](evaluation.md) page.
