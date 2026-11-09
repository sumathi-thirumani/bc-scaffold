import pytest

from src.tools import pull_requests_tool as tool_module
from src.models.gh.pull_request_metadata import PullRequestMetadata
from src.tools.pull_requests_tool import get_open_pull_requests, security_dependency_pull_requests_tool
from src.engines.resolvers.artifact_pr_resolver.pr_pattern_version_extractor import get_version_bumps


class StubResponse:
    status_code = 200
    def __init__(self, data, headers=None):
        self.data = data
        self.headers = headers or {}

    def raise_for_status(self):
        return None

    def json(self):
        return self.data


class StubAsyncClient:
    requests = []
    pages = []
    links = []
    headers = None

    def __init__(self, *, headers, timeout):
        type(self).headers = headers

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def get(self, url, params):
        type(self).requests.append({"url": url, "params": params})
        return StubResponse(type(self).pages.pop(0), {"Link": type(self).links.pop(0)})


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        (
            "Bump requests from 2.31.0 to 2.32.0",
            {"package": "requests", "from_version": "2.31.0", "to_version": "2.32.0"},
        ),
        (
            "Bump django from 4.2.1 to 4.2.2",
            {"package": "django", "from_version": "4.2.1", "to_version": "4.2.2"},
        ),
        (
            "Bump org.springframework:spring-core from 5.3.0 to 6.0.0",
            {
                "package": "org.springframework:spring-core",
                "from_version": "5.3.0",
                "to_version": "6.0.0",
            },
        ),
    ],
)
def test_parse_version_bump(title, expected):
    assert get_version_bumps("dependabot[bot]", title, "")[0].model_dump() == expected


def test_pull_request_metadata_model_normalizes_pull_request():
    metadata = PullRequestMetadata.from_pull_request(
        pull_request={
            "number": 7,
            "title": "Bump requests from 2.31.0 to 3.0.0",
            "head": {"ref": "dependabot/pip/requests-3.0.0"},
            "html_url": "https://github.com/octo-org/octo-repo/pull/7",
            "user": {"login": "dependabot[bot]"},
        },
        version_bumps=get_version_bumps("dependabot[bot]", "Bump requests from 2.31.0 to 3.0.0", ""),
    )

    assert metadata.model_dump() == {
        "pr_number": 7,
        "pr_title": "Bump requests from 2.31.0 to 3.0.0",
        "pr_branch": "dependabot/pip/requests-3.0.0",
        "pull_url": "https://github.com/octo-org/octo-repo/pull/7",
        "version_bumps": [
            {
                "package": "requests",
                "from_version": "2.31.0",
                "to_version": "3.0.0",
            }
        ],
        "severity": "",
        "author": "dependabot[bot]",
    }


@pytest.mark.asyncio
async def test_get_open_pull_requests_paginates(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(tool_module.httpx, "AsyncClient", StubAsyncClient)
    StubAsyncClient.requests = []
    StubAsyncClient.pages = [
        [{"number": index} for index in range(tool_module.PER_PAGE)],
        [{"number": tool_module.PER_PAGE}],
    ]
    StubAsyncClient.links = [
        '<https://api.github.com/repositories/1/pulls?page=2>; rel="next"',
        "",
    ]

    pull_requests = await get_open_pull_requests("octo-org", "octo-repo")

    assert len(pull_requests) == tool_module.PER_PAGE + 1
    assert StubAsyncClient.headers["Authorization"] == "Bearer token"
    assert StubAsyncClient.requests == [
        {
            "url": "https://api.github.com/repos/octo-org/octo-repo/pulls",
            "params": {"state": "open", "per_page": tool_module.PER_PAGE},
        },
        {
            "url": "https://api.github.com/repositories/1/pulls?page=2",
            "params": None,
        },
    ]


@pytest.mark.asyncio
async def test_security_dependency_pull_requests_tool_fetches_and_filters(monkeypatch):
    async def stub_get_open_pull_requests(owner, repo):
        return [
            {
                "number": 7,
                "title": "Bump requests from 2.31.0 to 2.32.0",
                "user": {"login": "dependabot[bot]"},
            }
        ]

    monkeypatch.setattr(tool_module, "get_open_pull_requests", stub_get_open_pull_requests)

    candidates = await security_dependency_pull_requests_tool.ainvoke(
        {
            "owner": "octo-org",
            "repo": "octo-repo",
        }
    )

    assert candidates[0]["pr_number"] == 7
    assert candidates[0]["author"] == "dependabot[bot]"
