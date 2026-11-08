#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parent.parent
ALIASES = json.loads((ROOT / "dev/label-aliases.json").read_text())
MOCK_GH = """#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
with open(os.environ["MOCK_CALLS"], "a") as log:
    log.write(json.dumps(args) + "\\n")
data = json.loads(os.environ["MOCK_DATA"])
if args[0] == "api":
    if data.get("api_failure"):
        sys.exit("Mock API failure")
    if args[1] != "graphql":
        print(json.dumps([[{"name": name} for name in data["available"]]]))
    elif "legacy: issues" in args[args.index("-f") + 1]:
        print(json.dumps(data["blockers"]))
    else:
        label = next(a[6:] for a in args if a.startswith("label="))
        print(json.dumps(data.get("matches", {}).get(label, [])))
elif args[:2] == ["issue", "view"]:
    if data.get("invalid_issue"):
        print("null")
        sys.exit(0)
    print(json.dumps({"labels": [{"name": n} for n in data.get("labels", [])]}))
elif args[:2] == ["issue", "create"]:
    print("https://example.invalid/issues/42")
elif args[:2] in (["issue", "edit"], ["issue", "comment"]):
    if data.get("write_failure"):
        sys.exit("Mock write failure")
else:
    sys.exit("Unexpected mock gh call: " + repr(args))
"""


class LabelMigrationTests(unittest.TestCase):
    def run_script(self, script, data, *args):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            gh = directory / "gh"
            gh.write_text(MOCK_GH)
            gh.chmod(0o755)
            calls = directory / "calls"
            env = dict(
                os.environ,
                PATH=f"{directory}{os.pathsep}{os.environ['PATH']}",
                GITHUB_REPOSITORY="test/repo",
                MOCK_DATA=json.dumps(data),
                MOCK_CALLS=str(calls),
                GITHUB_OUTPUT=str(directory / "output"),
            )
            result = subprocess.run(
                ["bash", "-c", script, "test", *args],
                cwd=ROOT, env=env, text=True, capture_output=True,
            )
            recorded = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
            return result, recorded

    def workflow_script(self, name):
        source = (ROOT / f".github/workflows/{name}.yml").read_text()
        script = re.search(r"run: \|\n(.*?)(?=\n\s+env:)", source, re.S).group(1)
        return textwrap.dedent(script).replace("${{ github.event.issue.number }}", "42")

    def category(self, labels):
        return subprocess.run(
            ["jq", "-e", "--slurpfile", "aliases", "dev/label-aliases.json",
             "-f", "dev/check-pr-labels.jq"],
            input=json.dumps({"labels": [{"name": n} for n in labels]}),
            cwd=ROOT, text=True, capture_output=True,
        ).returncode

    def test_category_aliases_count_once(self):
        for new in ("C-bug", "C-deps", "C-enhancement", "C-refactor"):
            old = ALIASES[new][0]
            for labels in ([old], [new], [new, old], [new, old, "A-docs"]):
                with self.subTest(labels=labels):
                    self.assertEqual(self.category(labels), 0)

    def test_documentation_needs_category_with_legacy_grace(self):
        for labels in (["kind/documentation"], ["A-docs", "C-bug"],
                       ["kind/documentation", "C-enhancement"]):
            self.assertEqual(self.category(labels), 0)
        for labels in ([], ["A-docs"], ["C-bug", "C-deps"],
                       ["kind/documentation", "C-bug", "C-refactor"]):
            self.assertNotEqual(self.category(labels), 0)

    def test_multiple_statuses_are_preserved(self):
        for labels in (["S-needs-review", "S-nominated"],
                       ["lifecycle/confirmed", "S-blocked"],
                       ["lifecycle/confirmed", "lifecycle/blocked"]):
            result, calls = self.run_script(
                'bash dev/ensure-issue-status.sh 42', {"labels": labels})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(calls), 1)

    def test_status_default_prefers_new_and_falls_back(self):
        for available, expected in (
            (["S-needs-triage", "lifecycle/needs-review"], "S-needs-triage"),
            (["lifecycle/needs-review"], "lifecycle/needs-review"),
        ):
            result, calls = self.run_script(
                'bash dev/ensure-issue-status.sh 42', {"available": available})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls[-1][-2:], ["--add-label", expected])

    def test_missing_status_fails(self):
        result, calls = self.run_script(
            'bash dev/ensure-issue-status.sh 42', {"available": []})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call[:2] == ["issue", "edit"] for call in calls))

    def test_release_blockers_either_name_and_both(self):
        issue = {"number": 42, "title": "Failure", "url": "https://example.invalid/42"}
        for old, new in ((0, 0), (1, 0), (0, 1), (1, 1), (0, 101)):
            data = {"blockers": {
                "legacy": {"totalCount": old, "nodes": [issue] if old else []},
                "structured": {"totalCount": new, "nodes": [issue] if new else []},
            }}
            result, calls = self.run_script('bash dev/check-release-blockers.sh test/repo', data)
            self.assertEqual(result.returncode, 1 if old or new else 0, result.stderr)
            query = calls[0][calls[0].index("-f") + 1]
            self.assertIn('labels: ["release-blocker"]', query)
            self.assertIn('labels: ["P-release-blocker"]', query)
            if old or new:
                self.assertEqual(result.stdout.count("#42:"), 1)

    def test_blocker_cleanup_removes_both(self):
        for labels in ([], ["P-release-blocker"], ["release-blocker"],
                       ["P-release-blocker", "release-blocker"]):
            result, calls = self.run_script(
                self.workflow_script("ReleaseBlockerLabelCleanUp"), {"labels": labels})
            self.assertEqual(result.returncode, 0, result.stderr)
            edits = [call[-1] for call in calls if call[:2] == ["issue", "edit"]]
            self.assertCountEqual(edits, labels)

    def notifier(self, data, labels="A-perf,A-testing,S-needs-triage,P-release-blocker"):
        return self.run_script(
            'bash dev/notify-ci-failure.sh "$@"', data, f"--labels={labels}")

    def test_notifier_existing_aliases_remain_discoverable(self):
        issue = {"number": 42, "url": "https://example.invalid/42"}
        requested = ["A-perf", "A-testing", "S-needs-triage", "P-release-blocker"]
        for available in (requested, [ALIASES[n][0] for n in requested],
                          requested + [ALIASES[n][0] for n in requested]):
            for key in ["A-perf"] + ALIASES["A-perf"]:
                result, calls = self.notifier({
                    "available": available, "matches": {key: [issue]}})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(any(call[:2] == ["issue", "create"] for call in calls))
                edit = next(call for call in calls if call[:2] == ["issue", "edit"])
                expected = "P-release-blocker" if "P-release-blocker" in available else "release-blocker"
                self.assertEqual(edit[-2:], ["--add-label", expected])

    def test_notifier_creates_with_resolved_labels(self):
        for requested in (
            ["A-testing", "C-bug", "A-fuzzing", "S-needs-triage"],
            ["A-ci-periodics", "A-testing", "S-needs-triage"],
            ["A-ci-periodics-aarch64", "A-ci-periodics", "A-testing", "S-needs-triage", "P-release-blocker"],
            ["A-ci-periodics-nightly", "A-ci-periodics", "A-testing", "S-needs-triage", "P-release-blocker"],
            ["A-ci-periodics-mshv-6.18", "A-ci-periodics", "A-testing", "S-needs-triage", "P-release-blocker"],
            ["A-fuzzing", "A-testing", "S-needs-triage", "P-release-blocker"],
        ):
            for available in (requested, [ALIASES[n][0] for n in requested]):
                result, calls = self.notifier({"available": available}, ",".join(requested))
                self.assertEqual(result.returncode, 0, result.stderr)
                create = next(call for call in calls if call[:2] == ["issue", "create"])
                self.assertEqual(create[create.index("--label") + 1:create.index("--repo"):2], available)

    def test_notifier_failures_never_create_duplicate(self):
        issue = {"number": 42, "url": "https://example.invalid/42"}
        for data in (
            {"available": []},
            {"api_failure": True},
            {"available": ["A-perf"], "api_failure": True},
            {"available": ["A-perf"], "matches": {"area/benchmarks": [issue]}, "write_failure": True},
            {"available": ["A-perf"], "matches": {"A-perf": None}},
        ):
            result, calls = self.notifier(data, "A-perf")
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(any(call[:2] == ["issue", "create"] for call in calls))

    def test_read_failures_fail_release_and_status(self):
        for script in ('bash dev/check-release-blockers.sh test/repo',
                       'bash dev/ensure-issue-status.sh 42'):
            result, _ = self.run_script(script, {"api_failure": True})
            self.assertNotEqual(result.returncode, 0)

    def test_invalid_issue_read_fails_without_edits(self):
        for script in ('bash dev/ensure-issue-status.sh 42',
                       self.workflow_script("ReleaseBlockerLabelCleanUp")):
            result, calls = self.run_script(script, {"invalid_issue": True})
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(any(call[:2] == ["issue", "edit"] for call in calls))

    def test_empty_notifier_labels_fail_without_calls(self):
        result, calls = self.notifier({}, "")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_existing_failure_status_is_not_reset(self):
        result, calls = self.notifier({
            "available": ["A-perf", "S-needs-triage"],
            "matches": {"area/performance": [{"number": 42, "url": "https://example.invalid/42"}]},
        }, "A-perf,S-needs-triage")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call[:2] == ["issue", "edit"] for call in calls))

    def test_golden_mode_accepts_either_label(self):
        workflow = (ROOT / ".github/workflows/ValidatePullRequest.yml").read_text()
        pattern = re.search(r"grep -Eqx '([^']+)'", workflow).group(1)
        for labels, expected in (
            ("", 1), ("A-docs", 1), ("regen-goldens", 0),
            ("S-needs-goldens", 0), ("regen-goldens\nS-needs-goldens", 0),
        ):
            result = subprocess.run(
                ["grep", "-Eqx", pattern], input=labels + "\n", text=True)
            self.assertEqual(result.returncode, expected)

    def test_static_producers_and_consumers_keep_aliases(self):
        dependabot = (ROOT / ".github/dependabot.yml").read_text()
        self.assertEqual(dependabot.count('"C-deps"'), 3)
        self.assertEqual(dependabot.count('"kind/dependencies"'), 3)
        self.assertNotIn("area/guest", dependabot)
        release = (ROOT / ".github/release.yml").read_text()
        self.assertEqual(release.count("C-deps"), 2)
        self.assertEqual(release.count("kind/dependencies"), 2)
        manage = (ROOT / ".github/workflows/ready-for-review-manage.yml").read_text()
        self.assertIn("label: [S-needs-review, ready-for-review]", manage)
        self.assertIn("label: ${{ matrix.label }}", manage)
        self.assertIn('workflows: ["Ready-for-review (collect)"]', manage)
        self.assertIn("name: ready-for-review-pr-number", manage)


if __name__ == "__main__":
    unittest.main()
