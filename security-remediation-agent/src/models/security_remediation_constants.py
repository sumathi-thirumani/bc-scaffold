
class SecurityRemediationConstants:

    """Define the supported ecosystem names shared by stages."""

    SUPPORTED_ECOSYSTEMS = frozenset(
        {"npm", "npm_and_yarn", "yarn", "pip", "pypi", "poetry", "nuget"}
    )

    ECOSYSTEM_GROUPS = {
        "python": frozenset({"pip", "pypi", "poetry"}),
        "npm": frozenset({"npm", "npm_and_yarn", "yarn"}),
        "npm/yarn/pnpm": frozenset({"npm", "npm_and_yarn", "yarn"}),
        "dotnet": frozenset({"nuget"}),
    }
