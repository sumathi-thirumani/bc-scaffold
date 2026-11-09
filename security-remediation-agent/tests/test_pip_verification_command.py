import subprocess
import tempfile
from pathlib import Path

import pytest

from src.engines.remediation_verification import pip_verification_engine, verification_engine


def test_uv_compile_uses_binary_only_without_conflicting_no_build(monkeypatch):
    captured = []

    def resolve(args, cwd):
        captured.append(args)
        (cwd / ".remediation-resolved.txt").write_text("fastapi==0.133.0\n", encoding="utf-8")

    monkeypatch.setattr(pip_verification_engine, "run", resolve)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        project = Path("api")
        (root / project).mkdir()
        (root / project / "requirements.in").write_text("fastapi>=0.70\n", encoding="utf-8")
        pip_verification_engine.PythonVerificationEngine().run_resolver(
            root, project, {project / "requirements.in": {"fastapi": "0.133.0"}},
        )
        assert (root / project / ".remediation-constraints.txt").read_text() == "fastapi==0.133.0\n"
    [command] = captured
    assert command[:4] == ["uv", "pip", "compile", "requirements.in"]
    assert command[command.index("--only-binary") + 1] == ":all:"
    assert "--no-build" not in command


def test_resolution_failure_includes_cli_diagnostics(monkeypatch):
    monkeypatch.setattr(verification_engine.shutil, "which", lambda name: "uv")
    monkeypatch.setattr(verification_engine.subprocess, "run", lambda *args, **kwargs:
        subprocess.CompletedProcess(args, 2, stdout="resolver context", stderr="argument conflict"))
    with pytest.raises(ValueError) as error:
        verification_engine.run(["uv", "pip", "compile", "requirements.in"], Path("."))
    assert "exit 2" in str(error.value)
    assert "argument conflict" in str(error.value)
    assert "resolver context" in str(error.value)



def test_resolver_subprocess_timeout_uses_remaining_manifest_budget(monkeypatch):
    import time
    captured = {}
    monkeypatch.setattr(verification_engine.shutil, 'which', lambda name: name)
    def completed(args, **kwargs):
        captured.update(kwargs)
        return subprocess.CompletedProcess(args, 0, stdout='', stderr='')
    monkeypatch.setattr(verification_engine.subprocess, 'run', completed)
    token = verification_engine.VERIFICATION_DEADLINE.set(time.monotonic() + 10)
    try:
        verification_engine.run(['npm', 'install'], Path('.'))
    finally:
        verification_engine.VERIFICATION_DEADLINE.reset(token)
    assert 0 < captured['timeout'] <= 10
