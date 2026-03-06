from __future__ import annotations

import logging
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

try:
    import gitlab
except ModuleNotFoundError as exc:
    if exc.name == "gitlab":
        gitlab = None  # type: ignore[assignment]
        _gitlab_import_error = exc
    else:
        raise
else:
    _gitlab_import_error = None

from repo_sanitizer.batch.config import ScopeConfig

logger = logging.getLogger(__name__)


@dataclass
class RepoTask:
    partner: str
    name: str
    clone_url: str    # authenticated HTTPS URL for cloning
    delivery_url: str  # authenticated HTTPS URL for push (filled by ensure_delivery_project)


class GitLabClient:
    def __init__(
        self,
        url: str,
        token: str,
        source_group: str,
        delivery_group: str,
    ) -> None:
        if gitlab is None:
            raise RuntimeError(
                "Missing dependency 'python-gitlab' required for batch mode. "
                "Install dependencies with `uv sync` or `pip install python-gitlab`."
            ) from _gitlab_import_error
        self.gl = gitlab.Gitlab(url, private_token=token)
        self.token = token
        self.source_group = source_group
        self.delivery_group = delivery_group

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def list_repos(self, scope: ScopeConfig) -> list[RepoTask]:
        """Return all RepoTask objects matching the given scope."""
        tasks: list[RepoTask] = []

        source = self.gl.groups.get(self.source_group)
        for sg in source.subgroups.list(all=True, iterator=True):
            partner_name = sg.path

            # Filter by partners/repos scope
            if scope.repos:
                # Check if any requested repo belongs to this partner
                partner_repos = {
                    r.split("/", 1)[1]
                    for r in scope.repos
                    if r.startswith(partner_name + "/")
                }
                if not partner_repos:
                    continue
            elif scope.partners:
                if partner_name not in scope.partners:
                    continue
            elif not scope.all:
                # Nothing selected — skip
                continue

            full_group = self.gl.groups.get(sg.id)
            for project in full_group.projects.list(all=True, iterator=True):
                if scope.repos:
                    if f"{partner_name}/{project.path}" not in scope.repos:
                        continue
                tasks.append(
                    RepoTask(
                        partner=partner_name,
                        name=project.path,
                        clone_url=self._auth_url(project.http_url_to_repo),
                        delivery_url="",  # filled later
                    )
                )

        logger.info("Enumerated %d repositories", len(tasks))
        return tasks

    # ------------------------------------------------------------------
    # Delivery project management
    # ------------------------------------------------------------------

    def ensure_delivery_project(self, partner: str, repo_name: str) -> str:
        """Create delivery group/project if needed. Returns authenticated push URL."""
        partner_group = self._ensure_delivery_partner_group(partner)

        namespace = f"{self.delivery_group}/{partner}"
        try:
            project = self.gl.projects.get(f"{namespace}/{repo_name}")
        except gitlab.exceptions.GitlabGetError:
            logger.debug("Creating delivery project %s/%s", namespace, repo_name)
            project = self.gl.projects.create(
                {
                    "name": repo_name,
                    "path": repo_name,
                    "namespace_id": partner_group.id,
                    "visibility": "private",
                    "initialize_with_readme": False,
                }
            )

        return self._auth_url(project.http_url_to_repo)

    def _ensure_delivery_partner_group(self, partner: str):
        namespace = f"{self.delivery_group}/{partner}"
        try:
            return self.gl.groups.get(namespace)
        except gitlab.exceptions.GitlabGetError:
            logger.debug("Creating delivery group %s", namespace)
            parent = self.gl.groups.get(self.delivery_group)
            return self.gl.groups.create(
                {
                    "name": partner,
                    "path": partner,
                    "parent_id": parent.id,
                    "visibility": "private",
                }
            )

    # ------------------------------------------------------------------
    # Bundle push
    # ------------------------------------------------------------------

    def push_bundle(self, bundle_path: Path, delivery_url: str) -> None:
        """Clone the git bundle into a temporary bare repo and mirror-push to delivery URL."""
        with tempfile.TemporaryDirectory(prefix="repo-san-push-") as tmp:
            tmp_path = Path(tmp) / "repo.git"

            logger.debug("Cloning bundle %s into %s", bundle_path, tmp_path)
            subprocess.run(
                ["git", "clone", "--bare", str(bundle_path), str(tmp_path)],
                check=True,
                capture_output=True,
                text=True,
            )

            logger.debug("Pushing to %s", delivery_url.split("@")[-1])
            subprocess.run(
                ["git", "push", "--mirror", delivery_url],
                cwd=tmp_path,
                check=True,
                capture_output=True,
                text=True,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _auth_url(self, http_url: str) -> str:
        """Embed oauth2 token into an HTTPS GitLab URL."""
        # https://gitlab.example.com/... → https://oauth2:<token>@gitlab.example.com/...
        if "://" not in http_url:
            return http_url
        scheme, rest = http_url.split("://", 1)
        return f"{scheme}://oauth2:{self.token}@{rest}"
