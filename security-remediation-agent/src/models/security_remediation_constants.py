
class SecurityRemediationConstants:

    DEFAULT_SEVERITIES = frozenset({"critical", "high", "medium", "low"})

    SUPPORTED_ECOSYSTEMS = frozenset(
        {"npm", "npm_and_yarn", "yarn", "pip", "pypi", "poetry", "nuget"}
    )
