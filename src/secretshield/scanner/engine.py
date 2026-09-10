"""High-performance repository and diff scanner for hardcoded secrets."""

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from rich.table import Table

from secretshield.proxy.redactor import calculate_shannon_entropy
from secretshield.scanner.rules import (
    DEFAULT_RULES,
    Finding,
    RuleDefinition,
    Severity,
    mask_token,
)


@dataclass
class ScanSummary:
    """Summary of a completed scan."""

    scanned_files_count: int = 0
    scanned_lines_count: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        """Check if any secrets were detected."""
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        """Count of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> dict[str, object]:
        """Serialize summary to a dictionary."""
        return {
            "scanned_files": self.scanned_files_count,
            "scanned_lines": self.scanned_lines_count,
            "total_findings": len(self.findings),
            "critical_findings": self.critical_count,
            "high_findings": self.high_count,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize summary to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_rich_table(self) -> Table:
        """Render findings as a Rich console table."""
        table = Table(
            title="SecretShield Repository Scan Results",
            header_style="bold magenta",
            show_header=True,
        )
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Rule", style="cyan", width=22)
        table.add_column("Location", style="yellow", width=28)
        table.add_column("Detected Secret (Masked)", style="red", width=24)
        table.add_column("Remediation", style="green")

        for f in self.findings:
            sev_style = {
                Severity.CRITICAL: "[bold red]CRITICAL[/bold red]",
                Severity.HIGH: "[bold yellow]HIGH[/bold yellow]",
                Severity.MEDIUM: "[yellow]MEDIUM[/yellow]",
                Severity.LOW: "[blue]LOW[/blue]",
            }.get(f.severity, f.severity.value)

            loc = f"{f.file_path}:{f.line_number}"
            table.add_row(
                sev_style,
                f.rule_name,
                loc,
                f.masked_secret,
                f.remediation,
            )
        return table

    def to_github_markdown(self) -> str:
        """Render findings formatted for GitHub Step Summary and PR comments."""
        if not self.has_findings:
            return (
                "### :white_check_mark: SecretShield Scan: No Secrets Detected\n\n"
                f"Scanned **{self.scanned_files_count}** files ({self.scanned_lines_count} lines). "
                "No hardcoded credentials, API keys, or private tokens were found."
            )

        md = [
            "### :rotating_light: SecretShield Security Alert: Hardcoded Secrets Detected\n",
            f"Scanned **{self.scanned_files_count}** files. Found **{len(self.findings)}** potential secret(s) "
            f"({self.critical_count} CRITICAL, {self.high_count} HIGH).\n",
            "| Severity | Rule | File:Line | Masked Secret | Recommended Action |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]

        for f in self.findings:
            sev_badge = f"`{f.severity.value}`"
            file_ref = f"`{f.file_path}:{f.line_number}`"
            md.append(
                f"| {sev_badge} | {f.rule_name} | {file_ref} | `{f.masked_secret}` | {f.remediation} |"
            )

        md.append("\n> **Important**: Do not commit secrets to source code. Use `secretshield vault set` "
                  "to store encrypted credentials in SecretShield and route outbound requests through the Zero-Trust proxy.")
        return "\n".join(md)

    def to_github_annotations(self) -> list[str]:
        """Generate GitHub Actions workflow command annotations (::error ...)."""
        annotations = []
        for f in self.findings:
            cmd = (
                f"::error file={f.file_path},line={f.line_number},title={f.rule_name}::"
                f"Hardcoded {f.rule_name} detected. {f.remediation}"
            )
            annotations.append(cmd)
        return annotations


class SecretScanner:
    """Core scanner for detecting hardcoded secrets in files, directories, and git diffs."""

    IGNORED_DIRS = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "dist",
        "build",
        "site-packages",
        ".idea",
        ".vscode",
    }

    BINARY_EXTENSIONS = {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".webp",
        ".svg",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".7z",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".pyc",
        ".pyo",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".class",
        ".jar",
        ".lock",
    }

    IGNORED_FILENAMES = {
        "uv.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "poetry.lock",
        "Cargo.lock",
    }

    HIGH_ENTROPY_WORD_REGEX = re.compile(
        r"(?:\b|(?<=[\s\"':=]))[A-Za-z0-9+/=_\-\$#@!]{24,}(?:\b|(?=[\s\"',;]))"
    )

    def __init__(
        self,
        rules: Sequence[RuleDefinition] | None = None,
        check_entropy: bool = True,
        entropy_threshold: float = 4.6,
        custom_ignore_patterns: Sequence[str] | None = None,
    ) -> None:
        self.rules = list(rules) if rules is not None else DEFAULT_RULES
        self.check_entropy = check_entropy
        self.entropy_threshold = entropy_threshold
        self.custom_ignore_patterns = list(custom_ignore_patterns or [])

    def is_path_ignored(self, path: Path) -> bool:
        """Check if a file or directory path should be skipped."""
        parts = set(path.parts)
        if parts & self.IGNORED_DIRS:
            return True

        if path.name in self.IGNORED_FILENAMES:
            return True

        if path.suffix.lower() in self.BINARY_EXTENSIONS:
            return True

        # Custom ignore patterns check
        path_str = str(path).replace("\\", "/")
        for pattern in self.custom_ignore_patterns:
            if pattern in path_str:
                return True

        return False

    def scan_line(self, line: str, file_path: str, line_num: int) -> list[Finding]:
        """Scan a single line of text for secrets."""
        findings: list[Finding] = []

        # 1. Check known pattern rules
        for rule in self.rules:
            for match in rule.pattern.finditer(line):
                raw_secret = match.group(0)
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=line_num,
                        column_start=match.start(),
                        column_end=match.end(),
                        line_content=line,
                        masked_secret=mask_token(raw_secret),
                        remediation=rule.remediation_hint,
                    )
                )

        # 2. Check high entropy tokens if enabled
        if self.check_entropy:
            for match in self.HIGH_ENTROPY_WORD_REGEX.finditer(line):
                candidate = match.group(0)
                # Avoid flagging strings already matched by specific rules
                if any(f.column_start <= match.start() and match.end() <= f.column_end for f in findings):
                    continue

                entropy = calculate_shannon_entropy(candidate)
                if entropy >= self.entropy_threshold:
                    findings.append(
                        Finding(
                            rule_id="SEC_ENTROPY",
                            rule_name="High-Entropy Secret Candidate",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=line_num,
                            column_start=match.start(),
                            column_end=match.end(),
                            line_content=line,
                            masked_secret=mask_token(candidate),
                            remediation="Verify if this is an API key or password; inject via SecretShield Vault.",
                        )
                    )

        return findings

    def scan_text(self, text: str, file_path: str = "<input>") -> list[Finding]:
        """Scan multi-line text for hardcoded secrets."""
        all_findings: list[Finding] = []
        for idx, line in enumerate(text.splitlines(), start=1):
            findings = self.scan_line(line, file_path, idx)
            all_findings.extend(findings)
        return all_findings

    def scan_file(self, file_path: Path) -> list[Finding]:
        """Scan an individual file if not ignored."""
        if self.is_path_ignored(file_path):
            return []

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            # Skip empty or binary null bytes
            if not content or "\x00" in content:
                return []
            return self.scan_text(content, str(file_path))
        except Exception:
            return []

    def scan_directory(self, dir_path: Path) -> ScanSummary:
        """Scan an entire directory recursively."""
        summary = ScanSummary()

        for path in dir_path.rglob("*"):
            if not path.is_file():
                continue
            if self.is_path_ignored(path):
                continue

            findings = self.scan_file(path)
            summary.scanned_files_count += 1
            try:
                summary.scanned_lines_count += len(path.read_text(encoding="utf-8", errors="replace").splitlines())
            except Exception:
                pass

            summary.findings.extend(findings)

        return summary

    def scan_git_diff(self, repo_path: Path, against: str = "origin/main") -> ScanSummary:
        """Scan only modified lines from git diff compared to a reference branch."""
        summary = ScanSummary()

        cmd = ["git", "-C", str(repo_path), "diff", "-U0", against]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            diff_text = res.stdout
        except Exception:
            return summary

        current_file = ""
        current_line = 0

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
                summary.scanned_files_count += 1
                continue

            if line.startswith("@@ "):
                # Chunk header: @@ -start,count +start,count @@
                match = re.search(r"\+(\d+)", line)
                if match:
                    current_line = int(match.group(1)) - 1
                continue

            if line.startswith("+") and not line.startswith("+++"):
                current_line += 1
                summary.scanned_lines_count += 1
                added_content = line[1:]

                path_obj = Path(current_file)
                if self.is_path_ignored(path_obj):
                    continue

                line_findings = self.scan_line(added_content, current_file, current_line)
                summary.findings.extend(line_findings)

        return summary
