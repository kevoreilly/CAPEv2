"""Regression gate: every compare SEED read is central-scoped (adversarial-review MEDIUM).

compare.left / hash / both authorize the SQL task (can_view_task) but must resolve the Mongo seed doc
through scoped_analysis_query in central mode -- else a colliding worker-local doc for another tenant
(same info.id) can shadow the seed, disclosing its target metadata in the panel and driving the md5
pivot from the wrong sample. This AST gate fails if any mongo_find_one("analysis", ...) seed read
reverts to a bare {"info.id": ...} filter. The md5-pivot uses mongo_find (not mongo_find_one) and is
already tenant-scoped via entitled_scope_filter + can_view_task post-filter, so it is out of scope here.
"""
import ast
import os


def _tree():
    src = os.path.join(os.path.dirname(__file__), "views.py")
    with open(src) as f:
        return ast.parse(f.read())


def _analysis_seed_reads(tree):
    out = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "mongo_find_one"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "analysis"
        ):
            out.append(node)
    return out


def _scoped_var_names(tree):
    """Local names assigned directly from scoped_analysis_query(...) (e.g. _lf/_rf in both())."""
    names = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "scoped_analysis_query"
        ):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
    return names


def test_every_compare_seed_read_routes_through_scoped_analysis_query():
    tree = _tree()
    reads = _analysis_seed_reads(tree)
    scoped_vars = _scoped_var_names(tree)
    assert reads, "expected mongo_find_one('analysis', ...) seed reads in compare/views.py"
    for node in reads:
        filt = node.args[1]
        # A bare {"info.id": ...} dict literal is the exact regression this gate guards against.
        assert not isinstance(filt, ast.Dict), (
            f"compare seed read at line {node.lineno} uses a bare dict filter -- must route through "
            f"scoped_analysis_query(request, ...)"
        )
        is_direct_call = (
            isinstance(filt, ast.Call) and isinstance(filt.func, ast.Name) and filt.func.id == "scoped_analysis_query"
        )
        is_scoped_var = isinstance(filt, ast.Name) and filt.id in scoped_vars
        assert is_direct_call or is_scoped_var, (
            f"compare seed read at line {node.lineno} filter must be scoped_analysis_query(request, ...) "
            f"or a local assigned from it, got {ast.dump(filt)}"
        )
