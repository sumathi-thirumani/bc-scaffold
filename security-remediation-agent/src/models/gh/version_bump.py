from pydantic import BaseModel


class VersionBump(BaseModel):
    """Represent one package transition from an old version to a proposed version in a PR."""
    package: str
    from_version: str
    to_version: str

    def __eq__(self, other: object) -> bool:
        if isinstance(other, dict):
            return self.model_dump() == other

        if isinstance(other, VersionBump):
            return self.model_dump() == other.model_dump()

        return super().__eq__(other)

    def __iter__(self):
        yield from self.model_dump().items()
