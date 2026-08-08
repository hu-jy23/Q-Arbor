"""Deterministic canonical JSON and self-contained HTML tree exports."""

from __future__ import annotations

import html
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from q_arbor.hypotheses import QHypothesisTree

_DEFAULT_TITLE = "Q-Arbor Hypothesis Tree"

_STYLE = """
:root { color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; }
body { margin: 0 auto; max-width: 1120px; padding: 2rem; color: #172033; background: #f5f7fb; }
h1, h2, h3 { line-height: 1.2; }
.summary, .compatibility, .node, .canonical { background: #fff; border: 1px solid #d9dfeb; border-radius: .6rem; margin: 1rem 0; padding: 1rem 1.2rem; }
.compatibility { border-left: .45rem solid #b45309; background: #fffbeb; }
.node { margin-left: min(calc(var(--depth) * 1.25rem), 8rem); }
.badge { display: inline-block; border-radius: 999px; padding: .15rem .55rem; background: #e8edf7; font-size: .82rem; }
dl { display: grid; grid-template-columns: minmax(9rem, 15rem) 1fr; gap: .45rem .9rem; }
dt { color: #4b5563; font-weight: 650; }
dd { margin: 0; overflow-wrap: anywhere; }
ul { padding-left: 1.35rem; }
pre { background: #111827; color: #e5e7eb; overflow: auto; padding: 1rem; white-space: pre-wrap; overflow-wrap: anywhere; }
.muted { color: #5f6b7c; }
""".strip()


def export_tree_json(tree: QHypothesisTree) -> str:
    """Return the model's canonical compact UTF-8 JSON representation."""

    checked = _checked_tree(tree)
    return checked.to_json()


def render_tree_html(tree: QHypothesisTree, *, title: str = _DEFAULT_TITLE) -> str:
    """Render a deterministic, dependency-free, fully escaped tree report."""

    checked = _checked_tree(tree)
    if not isinstance(title, str):
        raise TypeError("title must be a string")
    mapping = checked.to_dict()
    canonical_json = checked.to_json()
    escaped_title = _escape(title)

    parts = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{escaped_title}</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        f"<h1>{escaped_title}</h1>",
        '<section class="summary">',
        "<h2>Run summary</h2>",
        "<dl>",
        _definition("Run ID", mapping.get("run_id")),
        _definition("Contract hash", mapping.get("contract_hash")),
        _definition("Revision", mapping.get("revision")),
        _definition("Run state", mapping.get("run_state")),
        _definition("Root node", mapping.get("root_node_id")),
        _definition("Counts", mapping.get("counts")),
        "</dl>",
        "</section>",
    ]

    compatibility = mapping.get("compatibility")
    if isinstance(compatibility, Mapping):
        parts.extend(_compatibility_html(compatibility))

    parts.extend(("<main>", "<h2>Hypothesis nodes</h2>"))
    nodes = mapping.get("nodes")
    if not isinstance(nodes, list):
        raise TypeError("QHypothesisTree.to_dict() returned invalid nodes")
    for raw_node in nodes:
        if not isinstance(raw_node, Mapping):
            raise TypeError("QHypothesisTree.to_dict() returned an invalid node")
        parts.extend(_node_html(raw_node))
    parts.extend(
        (
            "</main>",
            '<section class="canonical">',
            "<h2>Canonical JSON</h2>",
            '<pre id="canonical-json">' + _escape(canonical_json) + "</pre>",
            "</section>",
            "</body>",
            "</html>",
        )
    )
    return "\n".join(parts) + "\n"


def write_tree_html(
    tree: QHypothesisTree,
    path: str | os.PathLike[str],
    *,
    title: str = _DEFAULT_TITLE,
) -> None:
    """Atomically write deterministic UTF-8 HTML beside its destination."""

    content = render_tree_html(tree, title=title).encode("utf-8")
    destination = Path(path)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = temporary.name
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except (OSError, TypeError, ValueError) as exc:
        from q_arbor.hypotheses import TreePersistenceError

        raise TreePersistenceError("unable to atomically write tree HTML") from exc
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def _checked_tree(tree: object) -> QHypothesisTree:
    from q_arbor.hypotheses import QHypothesisTree

    if not isinstance(tree, QHypothesisTree):
        raise TypeError("tree must be a QHypothesisTree")
    return tree


def _compatibility_html(compatibility: Mapping[str, Any]) -> list[str]:
    missing = compatibility.get("missing_fields_by_node")
    scores = compatibility.get("legacy_scores_by_node")
    dropped = compatibility.get("dropped_meta_keys")
    missing_count = len(missing) if isinstance(missing, Mapping) else 0
    score_count = 0
    if isinstance(scores, Mapping):
        for record in scores.values():
            if isinstance(record, Mapping) and (
                record.get("score_source") is not None
                or record.get("test_score") is not None
            ):
                score_count += 1
    dropped_count = (
        len(dropped)
        if isinstance(dropped, Sequence) and not isinstance(dropped, (str, bytes))
        else 0
    )
    return [
        '<aside class="compatibility">',
        "<h2>Compatibility quarantine</h2>",
        "<p>Legacy Arbor facts are retained for audit and cannot support Q-node scoring or insight propagation.</p>",
        "<ul>",
        f"<li>Source: {_escape(_display(compatibility.get('source')))} (version {_escape(_display(compatibility.get('source_version')))})</li>",
        f"<li>Nodes with explicit missing-field flags: {missing_count}</li>",
        f"<li>Nodes with quarantined legacy scores: {score_count}</li>",
        f"<li>Dropped legacy metadata keys: {dropped_count}</li>",
        "<li>Missing source time uses the deterministic 1970-01-01T00:00:00Z import sentinel.</li>",
        "</ul>",
        "<dl>",
        _definition("Safe legacy metadata", compatibility.get("safe_meta")),
        _definition("Dropped-key labels", dropped),
        "</dl>",
        "</aside>",
    ]


def _node_html(node: Mapping[str, Any]) -> list[str]:
    depth = node.get("depth")
    if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
        raise TypeError("QHypothesisTree.to_dict() returned an invalid node depth")
    hypothesis = _mapping(node.get("hypothesis"), "node hypothesis")
    scope = _mapping(node.get("scope"), "node scope")
    failure = _mapping(node.get("failure"), "node failure")
    evidence = _sequence(node.get("evidence_refs"), "node evidence_refs")
    insights = _sequence(node.get("insights"), "node insights")

    lines = [
        f'<article class="node" style="--depth: {depth}">',
        f"<h3>{_escape(_display(node.get('id')))}</h3>",
        f'<span class="badge">status: {_escape(_display(node.get("status")))}</span> ',
        f'<span class="badge">admissibility: {_escape(_display(node.get("admissibility")))}</span>',
        "<dl>",
        _definition("Parent", node.get("parent_id")),
        _definition("Children", node.get("children_ids")),
        _definition("Score", node.get("score")),
        _definition("Mechanism", hypothesis.get("mechanism")),
        _definition("Prediction", hypothesis.get("falsifiable_prediction")),
        _definition("Observable", hypothesis.get("observable")),
        _definition("Single change", hypothesis.get("single_change")),
        _definition("Scope", scope),
        _definition("Failure type", failure.get("failure_type")),
        _definition("Failure summary", failure.get("summary")),
        "</dl>",
        "<h4>Evidence</h4>",
    ]
    if not evidence:
        lines.append('<p class="muted">None recorded.</p>')
    else:
        lines.append("<ul>")
        for raw_evidence in evidence:
            record = _mapping(raw_evidence, "evidence record")
            text = (
                f"{_display(record.get('evidence_id'))}: "
                f"level={_display(record.get('level'))}, "
                f"status={_display(record.get('status'))}, "
                f"split={_display(record.get('split_role'))}, "
                f"claim={_display(record.get('claim'))}"
            )
            lines.append(f"<li>{_escape(text)}</li>")
        lines.append("</ul>")
    lines.append("<h4>Insights</h4>")
    if not insights:
        lines.append('<p class="muted">None recorded.</p>')
    else:
        lines.append("<ul>")
        for raw_insight in insights:
            record = _mapping(raw_insight, "insight record")
            text = (
                f"{_display(record.get('insight_id'))}: "
                f"grade={_display(record.get('grade'))}, "
                f"validity={_display(record.get('validity'))}, "
                f"{_display(record.get('text'))}"
            )
            lines.append(f"<li>{_escape(text)}</li>")
        lines.append("</ul>")
    lines.append("</article>")
    return lines


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field} must be a mapping")
    return cast(Mapping[str, Any], value)


def _sequence(value: object, field: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TypeError(f"{field} must be a sequence")
    return cast(Sequence[Any], value)


def _definition(label: str, value: object) -> str:
    return f"<dt>{_escape(label)}</dt><dd>{_escape(_display(value))}</dd>"


def _display(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, Mapping):
        items = ", ".join(
            f"{key}={_display(item)}" for key, item in sorted(value.items())
        )
        return "{" + items + "}"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return "[" + ", ".join(_display(item) for item in value) + "]"
    raise TypeError("tree export contains a non-displayable value")


def _escape(value: str) -> str:
    return html.escape(value, quote=True)


__all__ = ["export_tree_json", "render_tree_html", "write_tree_html"]
