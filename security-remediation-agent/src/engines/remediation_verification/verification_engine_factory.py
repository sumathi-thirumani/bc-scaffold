"""Select a resolution engine by package ecosystem."""
from .upgrade_verifier import NpmVerificationEngine, PythonVerificationEngine, UnsupportedVerification


class VerificationEngineFactory:
    def create(self, ecosystem):
        if ecosystem.lower() in {"npm", "npm_and_yarn"}:
            return NpmVerificationEngine()
        if ecosystem.lower() in {"pip", "pypi", "python", "poetry", "uv"}:
            return PythonVerificationEngine()
        raise UnsupportedVerification(f"Resolution-only verification is not supported for {ecosystem}")
