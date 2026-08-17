"""Checks that read the configuration itself, not the server's tool surface.

These are the checks that make tier `config` worth running: they need no
running server, no network, and no captured snapshot. What a config file
contains — the command, its arguments, environment variable names and values,
the transport and URL — is a real attack surface. A server that is launched by
piping a remote script into a shell is a supply-chain problem before its first
tool description is read.

REDACTION. Environment values are matched but never emitted, not even masked.
The existing metadata check masks values because a tool description is
server-supplied text that the operator may need to see; an environment value is
the operator's own credential and there is no version of printing it that
helps. Findings name the variable and the pattern class only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from mcpscan.capabilities import Capability
from mcpscan.checks.base import Check
from mcpscan.checks.secrets import SECRET_PATTERNS
from mcpscan.models import Finding, FindingScope, ScanContext, Severity
from mcpscan.tiers import ALL_TIERS

# ---------------------------------------------------------------- MCP-060


class SecretInConfiguredEnvironmentCheck(Check):
    id = "MCP-060"
    title = "Secret value in configured environment"
    severity = Severity.CRITICAL
    default_capability = Capability.CREDENTIAL_ACCESS
    owasp_mcp = "MCP01"
    requires = ALL_TIERS
    scope = FindingScope.CONFIGURATION

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for name in sorted(ctx.target.env):
            value = ctx.target.env[name]
            label = _secret_label(value)
            if label is None:
                continue
            findings.append(
                self.finding(
                    target=f"env:{name}",
                    # Name and class only. The value is never emitted, masked
                    # or otherwise — it is the operator's own credential.
                    evidence=(
                        f"Environment variable {name} in the MCP configuration holds a value "
                        f"matching a {label}. The value was not read into the report."
                    ),
                    remediation=(
                        "Keep credentials out of MCP config files. Reference a secret manager or "
                        "an environment injected at launch, and rotate anything already committed."
                    ),
                    metadata={"env_name": name, "pattern": label},
                )
            )
        return findings


def _secret_label(value: str) -> str | None:
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(value):
            return label
    return None


# ---------------------------------------------------------------- MCP-061

#: Shell metacharacters that turn one argument into two commands.
_SHELL_COMPOSITION = re.compile(r"(?:\|\||&&|;|\$\(|`|\|)")

#: Fetch-and-execute, in the shapes people actually write.
_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python\d?|node|iex)\b",
    re.I,
)

#: Environment values that switch off transport verification.
_TLS_DISABLING: dict[str, tuple[str, ...]] = {
    "NODE_TLS_REJECT_UNAUTHORIZED": ("0",),
    "PYTHONHTTPSVERIFY": ("0",),
    "CURL_INSECURE": ("1", "true"),
    "GIT_SSL_NO_VERIFY": ("1", "true"),
    "REQUESTS_CA_BUNDLE": (),  # empty value disables verification
    "SSL_CERT_FILE": (),
}


class DangerousLaunchCommandCheck(Check):
    id = "MCP-061"
    title = "Dangerous launch command or configuration"
    severity = Severity.HIGH
    default_capability = Capability.SHELL_EXEC
    owasp_mcp = "MCP05"
    requires = ALL_TIERS
    scope = FindingScope.CONFIGURATION

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        command = ctx.target.command or []
        joined = " ".join(command)

        if command and _PIPE_TO_SHELL.search(joined):
            findings.append(
                self.finding(
                    owasp_mcp="MCP04",
                    capability=Capability.NETWORK_EGRESS,
                    target=_command_label(command),
                    evidence=(
                        "The launch command downloads a remote script and pipes it into a shell. "
                        "Whatever that URL serves at launch time runs with your privileges, and "
                        "it can differ between runs."
                    ),
                    remediation=(
                        "Install the server from a pinned package or a checked-out revision, and "
                        "launch the installed entry point instead of fetching a script."
                    ),
                )
            )

        for index, arg in enumerate(command):
            if _SHELL_COMPOSITION.search(arg):
                findings.append(
                    self.finding(
                        target=_command_label(command),
                        evidence=(
                            f"Launch argument {index} contains shell composition characters, so the "
                            "configured command is more than one command."
                        ),
                        remediation=(
                            "Pass a single executable and its arguments. If a shell is genuinely "
                            "required, move the logic into a script file you control."
                        ),
                        metadata={"argument_index": str(index)},
                    )
                )
                break

        if command and command[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1] == "sudo":
            findings.append(
                self.finding(
                    capability=Capability.SHELL_EXEC,
                    owasp_mcp="MCP02",
                    target=_command_label(command),
                    evidence="The server is launched with sudo, so it runs with elevated privileges.",
                    remediation="Run MCP servers as an unprivileged user.",
                )
            )

        for name in sorted(ctx.target.env):
            value = ctx.target.env[name]
            disabling = _TLS_DISABLING.get(name.upper())
            if disabling is None:
                continue
            hit = value.strip().lower() in disabling if disabling else value.strip() == ""
            if hit:
                findings.append(
                    self.finding(
                        owasp_mcp="MCP07",
                        capability=Capability.TRANSPORT_SECURITY,
                        severity=Severity.HIGH,
                        target=f"env:{name}",
                        evidence=(
                            f"{name} is set to a value that disables TLS certificate verification "
                            "for this server's outbound connections."
                        ),
                        remediation=(
                            "Remove the override and fix the underlying certificate problem. "
                            "Disabled verification makes interception undetectable."
                        ),
                        metadata={"env_name": name},
                    )
                )
        return findings


# ---------------------------------------------------------------- MCP-062

_RUNNERS = {"npx", "bunx", "uvx", "pnpx", "dlx"}
#: `pipx run pkg`, `uv tool run pkg` — runner is the second token.
_TWO_WORD_RUNNERS = {("pipx", "run"), ("uv", "tool"), ("bun", "x")}
_RUNNER_FLAGS = {"-y", "--yes", "-q", "--quiet", "--silent", "-p", "--package", "--from"}
_VCS_SPEC = re.compile(r"^(?:git\+|github:|gitlab:|https?://)", re.I)
#: npm-style pin: name@1.2.3, @scope/name@1.2.3. Also accepts a sha or tag.
_PINNED = re.compile(r"^(@[^/@\s]+/)?[^@\s]+@(?!latest\b|next\b|beta\b|\*)[^@\s]+$")


class UnpinnedServerPackageCheck(Check):
    id = "MCP-062"
    title = "Unpinned server package"
    severity = Severity.MEDIUM
    default_capability = Capability.OTHER
    owasp_mcp = "MCP04"
    requires = ALL_TIERS
    scope = FindingScope.CONFIGURATION

    def run(self, ctx: ScanContext) -> list[Finding]:
        command = ctx.target.command or []
        spec = _package_spec(command)
        if spec is None:
            return []

        if _VCS_SPEC.match(spec):
            reason = "a version-control or URL specifier, whose contents can change at any time"
        elif re.search(r"@(latest|next|beta|\*)$", spec, re.I):
            reason = "an explicitly floating tag"
        elif _PINNED.match(spec):
            return []
        else:
            reason = "no version, so the runner resolves the newest release at every launch"

        return [
            self.finding(
                target=spec,
                evidence=(
                    f"The server is launched via a package runner with {reason}. "
                    "A rug pull needs no access to your machine: publishing a new version is enough."
                ),
                remediation=(
                    "Pin an exact version, and re-pin deliberately. `mcpscan snapshot` plus "
                    "`mcpscan drift` will show when a pinned surface changes anyway."
                ),
                metadata={"specifier": spec},
            )
        ]


def _package_spec(command: list[str]) -> str | None:
    if not command:
        return None
    head = command[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    head = head[:-4] if head.endswith(".exe") else head
    rest = command[1:]

    if head not in _RUNNERS:
        if len(command) >= 2 and (head, command[1].lower()) in _TWO_WORD_RUNNERS:
            rest = command[2:]
        else:
            return None

    for arg in rest:
        if arg in _RUNNER_FLAGS or arg.startswith("-"):
            continue
        return arg
    return None


# ---------------------------------------------------------------- MCP-063

#: Paths that hand over a whole tree rather than a working directory.
_BROAD_POSIX = {
    "/",
    "/home",
    "/Users",
    "/etc",
    "/var",
    "/usr",
    "/opt",
    "/mnt",
    "/media",
    "/private",
}
_HOME_TOKENS = {"~", "~/", "$HOME", "${HOME}", "%USERPROFILE%", "$env:USERPROFILE"}
_BROAD_WINDOWS = re.compile(r"^[a-z]:[\\/]?$|^[a-z]:[\\/]users[\\/]?$", re.I)


class BroadFilesystemGrantCheck(Check):
    id = "MCP-063"
    title = "Broad filesystem path granted in configuration"
    severity = Severity.HIGH
    default_capability = Capability.FILE_READ
    owasp_mcp = "MCP02"
    requires = ALL_TIERS
    scope = FindingScope.CONFIGURATION

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for index, arg in enumerate(ctx.target.command or []):
            breadth = _path_breadth(arg)
            if breadth is None:
                continue
            findings.append(
                self.finding(
                    severity=breadth[0],
                    target=arg,
                    evidence=(
                        f"Launch argument {index} grants access to {breadth[1]}. Every tool this "
                        "server exposes can reach anything under it."
                    ),
                    remediation=(
                        "Grant the narrowest directory the server actually needs. A project "
                        "directory is almost always enough."
                    ),
                    metadata={"argument_index": str(index), "path": arg},
                )
            )
        return findings


def _path_breadth(arg: str) -> tuple[Severity, str] | None:
    value = arg.strip().rstrip("/\\") or "/"
    stripped = arg.strip()

    if stripped in _HOME_TOKENS or value in _HOME_TOKENS:
        return Severity.HIGH, "the entire home directory"
    if value == "":
        return None
    if _BROAD_WINDOWS.match(stripped) or _BROAD_WINDOWS.match(f"{value}\\"):
        return Severity.HIGH, "an entire Windows drive or all user profiles"
    if stripped == "/":
        return Severity.HIGH, "the filesystem root"
    if value in _BROAD_POSIX:
        return Severity.HIGH, f"the whole of {value}"
    # A direct child of /Users or /home is one user's entire account.
    if re.fullmatch(r"/(?:Users|home)/[^/]+", value):
        return Severity.HIGH, "an entire user account directory"
    return None


def _command_label(command: list[str]) -> str:
    return command[0] if command else "command"


def iter_config_checks() -> Iterable[Check]:
    yield SecretInConfiguredEnvironmentCheck()
    yield DangerousLaunchCommandCheck()
    yield UnpinnedServerPackageCheck()
    yield BroadFilesystemGrantCheck()
