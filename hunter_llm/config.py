"""Central configuration via environment variables and defaults."""

from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HUNTER_", env_file=".env", extra="ignore")

    data_root: Path = Field(default_factory=lambda: Path("data"))
    raw_dir: Path | None = None
    processed_dir: Path | None = None

    # NVD API 2.0 — request a key at https://nvd.nist.gov/developers/request-an-api-key
    nvd_api_key: str | None = None

    github_token: str | None = Field(
        default=None,
        description="Optional GitHub token for higher API rate limits when listing repo files.",
    )

    @model_validator(mode="after")
    def resolve_paths(self):
        root = self.data_root.expanduser().resolve()
        raw = self.raw_dir.expanduser().resolve() if self.raw_dir else root / "raw"
        proc = self.processed_dir.expanduser().resolve() if self.processed_dir else root / "processed"
        self.data_root = root
        self.raw_dir = raw
        self.processed_dir = proc
        return self


settings = Settings()


# Curated security / bug-hunting repositories. `paths` is a list of repo-relative path
# prefixes to keep (None means keep the whole repo). This keeps clones manageable.
DEFAULT_REPOS: list[dict] = [
    {
        "owner": "swisskyrepo",
        "repo": "PayloadsAllTheThings",
        "license": "MIT",
        "paths": None,
    },
    {
        "owner": "danielmiessler",
        "repo": "SecLists",
        "license": "MIT",
        # Methodology/readme-style paths only — exclude Passwords, Web-Shells, huge wordlists.
        "paths": ["README.md", "Discovery", "Fuzzing", "Pattern-Matching", "Miscellaneous"],
    },
    {
        "owner": "projectdiscovery",
        "repo": "nuclei-templates",
        "license": "MIT",
        "paths": ["http", "dns", "ssl", "network", "code", "javascript", "headless", "workflows", "README.md"],
    },
    {
        "owner": "OWASP",
        "repo": "CheatSheetSeries",
        "license": "CC-BY-SA-4.0",
        "paths": ["cheatsheets"],
    },
    {
        "owner": "OWASP",
        "repo": "wstg",
        "license": "CC-BY-SA-4.0",
        "paths": ["document"],
    },
    {
        "owner": "OWASP",
        "repo": "ASVS",
        "license": "CC-BY-SA-4.0",
        "paths": ["4.0"],
    },
    {
        "owner": "rapid7",
        "repo": "metasploit-framework",
        "license": "BSD-3-Clause",
        # Markdown docs per module: Name/Description/References/Targets — perfect for instructions.
        "paths": ["documentation/modules"],
    },
    {
        "owner": "nahamsec",
        "repo": "Resources-for-Beginner-Bug-Bounty-Hunters",
        "license": "Public-Domain",
        "paths": None,
    },
    {
        "owner": "jhaddix",
        "repo": "tbhm",
        "license": "MIT",
        "paths": None,
    },
    {
        "owner": "reddelexc",
        "repo": "hackerone-reports",
        "license": "MIT",
        "paths": ["tops_by_bug_type", "README.md"],
    },
    {
        "owner": "Hari-prasaanth",
        "repo": "Web-App-Pentest-Checklist",
        "license": "MIT",
        "paths": None,
    },
    {
        "owner": "harshinsecurity",
        "repo": "web-pentesting-checklist",
        "license": "MIT",
        "paths": None,
    },
    {
        "owner": "dwisiswant0",
        "repo": "awesome-oneliner-bugbounty",
        "license": "Apache-2.0",
        "paths": None,
    },
    {
        "owner": "infoslack",
        "repo": "awesome-web-hacking",
        "license": "Other",
        "paths": None,
    },
    {
        "owner": "EdOverflow",
        "repo": "bugbounty-cheatsheet",
        "license": "CC0-1.0",
        "paths": None,
    },
    {
        "owner": "ngalongc",
        "repo": "bug-bounty-reference",
        "license": "MIT",
        "paths": None,
    },
    # === Added in expansion: writeup aggregators, OWASP guides, internal/AD, taxonomy ===
    {
        "owner": "OWASP",
        "repo": "owasp-mastg",
        "license": "CC-BY-SA-4.0",
        "paths": ["Document", "tests"],
    },
    {
        "owner": "OWASP",
        "repo": "API-Security",
        "license": "CC-BY-SA-4.0",
        "paths": ["editions"],
    },
    {
        "owner": "OWASP",
        "repo": "Top10",
        "license": "CC-BY-SA-4.0",
        "paths": ["2021/docs"],
    },
    {
        "owner": "swisskyrepo",
        "repo": "InternalAllTheThings",
        "license": "MIT",
        "paths": None,
    },
    {
        "owner": "Ignitetechnologies",
        "repo": "Mindmap",
        "license": "Other",
        "paths": None,
    },
    {
        "owner": "0xInfection",
        "repo": "Awesome-WAF",
        "license": "CC-BY-4.0",
        "paths": None,
    },
    {
        "owner": "bugcrowd",
        "repo": "vulnerability-rating-taxonomy",
        "license": "Apache-2.0",
        "paths": None,
    },
    {
        "owner": "devanshbatham",
        "repo": "Awesome-Bugbounty-Writeups",
        "license": "MIT",
        "paths": None,
    },
    {
        "owner": "kh4sh3i",
        "repo": "Bug-Bounty-Writeups",
        "license": "MIT",
        "paths": None,
    },
    {
        "owner": "qazbnm456",
        "repo": "awesome-web-security",
        "license": "CC-BY-4.0",
        "paths": None,
    },
]


TEXT_EXTENSIONS = {
    ".md",
    ".markdown",
    ".rst",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
    ".py",
    ".rb",
    ".sh",
    ".ps1",
    ".jsp",
    ".php",
    ".java",
    ".c",
    ".h",
    ".go",
    ".rs",
}

MAX_FILE_BYTES = 512_000  # skip huge binaries / dumps
