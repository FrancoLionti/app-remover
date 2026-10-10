"""Safety and integration tests. Native removals are always mocked."""

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app_remover.cli import main
from app_remover.execution import execute
from app_remover.inventory import (
    appimage_apps,
    apt_apps,
    extension_apps,
    flatpak_apps,
    flatpak_flag,
    snap_apps,
)
from app_remover.model import App, Inventory, Refusal
from app_remover.planning import make_plan, resolve
from app_remover.runtime import clean, parse_size


def apt(name="demo", protected=False):
    return App(
        "apt:" + name,
        "apt",
        name,
        name,
        "1.0",
        size_bytes=1024,
        protected=protected,
        fingerprint="1.0",
    )


def flatpak(name="org.example.Demo", scope="system"):
    ref = name + "/x86_64/stable"
    return App(
        f"flatpak:{scope}:{ref}",
        "flatpak",
        ref,
        name.split(".")[-1],
        scope=scope,
        fingerprint="abc",
    )


class ResolutionTests(unittest.TestCase):
    def test_duplicate_formats_require_explicit_choice(self):
        inventory = Inventory([apt(), flatpak()])
        with self.assertRaisesRegex(Refusal, "ambigua"):
            resolve(["demo"], inventory)

    def test_explicit_id_and_deduplication(self):
        app = apt()
        self.assertEqual(resolve(["apt:demo", "apt:demo"], Inventory([app])), [app])

    def test_all_inputs_resolved_before_any_mutation(self):
        with self.assertRaisesRegex(Refusal, "No encontré"):
            resolve(["demo", "missing"], Inventory([apt()]))

    def test_unavailable_backend_cannot_hide_duplicate(self):
        inventory = Inventory([apt()], {"snap": "timeout"})
        with self.assertRaisesRegex(Refusal, "incompleto"):
            resolve(["demo"], inventory)
        self.assertEqual(resolve(["apt:demo"], inventory), [apt()])

    def test_system_packages_are_blocked(self):
        with self.assertRaisesRegex(Refusal, "protección"):
            resolve(["apt:demo"], Inventory([apt(protected=True)]))

    def test_option_and_punctuation_selectors_rejected(self):
        for selector in ("--purge", "", "$()", "apt:demo;touch /tmp/pwned"):
            with self.subTest(selector=selector), self.assertRaises(Refusal):
                resolve([selector], Inventory([apt()]))

    def test_interactive_selection_can_choose_two_formats(self):
        apps = [apt(), flatpak()]
        self.assertEqual(resolve(["demo"], Inventory(apps), lambda _, values: values), apps)

    def test_gsconnect_package_and_user_extension_are_ambiguous(self):
        apps = [
            apt("gnome-shell-extension-gsconnect"),
            App(
                "extension:gsconnect@example.org", "extension", "gsconnect@example.org", "GSConnect"
            ),
        ]
        with self.assertRaisesRegex(Refusal, "ambigua"):
            resolve(["gsconnect"], Inventory(apps))

    def test_plan_surfaces_unselected_matching_installation(self):
        app = flatpak()
        plan = make_plan([app], Inventory([app, apt()]))
        self.assertTrue(any("apt:demo" in note for note in plan.notes))


class PlanningTests(unittest.TestCase):
    def plan_apt(self, output, apps=None, inventory=None):
        apps = apps or [apt()]
        inventory = inventory or Inventory(apps)

        def capture(argv, **kwargs):
            return output if "-s" in argv else "/usr/lib/systemd/system/demo.service\n"

        with patch("app_remover.planning.capture", side_effect=capture):
            return make_plan(apps, inventory)

    def test_apt_surfaces_additional_dependents_and_sizes(self):
        plan = self.plan_apt(
            "Remv demo [1.0]\nRemv dependent [1.0]\n",
            inventory=Inventory([apt(), apt("dependent")]),
        )
        step = plan.steps[0]
        self.assertEqual(step.affected, ["demo", "dependent"])
        self.assertEqual(step.estimated_bytes, 2048)
        self.assertIn("APT::Get::AutomaticRemove=false", step.argv)
        self.assertNotIn("-y", step.argv)
        self.assertNotIn("purge", step.argv)
        self.assertTrue(any("unidades de servicio" in note for note in step.notes))

    def test_apt_blocks_protected_dependency(self):
        with self.assertRaisesRegex(Refusal, "protegido"):
            self.plan_apt(
                "Remv demo\nRemv libc6\n",
                inventory=Inventory([apt(), apt("libc6", protected=True)]),
            )

    def test_apt_blocks_install_configure_and_purge(self):
        for operation in ("Inst", "Conf", "Purg"):
            with self.subTest(operation=operation), self.assertRaises(Refusal):
                self.plan_apt("Remv demo\n" + operation + " other\n")

    def test_apt_blocks_unknown_package(self):
        with self.assertRaisesRegex(Refusal, "sin identificar"):
            self.plan_apt("Remv demo\nRemv surprise\n")

    def test_apt_missing_target_blocks(self):
        with self.assertRaises(Refusal):
            self.plan_apt("Remv other\n", inventory=Inventory([apt(), apt("other")]))

    def test_apt_multiarch_names_are_resolved(self):
        app = apt("demo:amd64")
        plan = self.plan_apt("Remv demo [1.0]\n", [app], Inventory([app]))
        self.assertEqual(plan.steps[0].estimated_bytes, 1024)

    def test_flatpak_preserves_data_and_scope(self):
        for scope, flag in (
            ("user", "--user"),
            ("system", "--system"),
            ("custom", "--installation=custom"),
        ):
            app = flatpak(scope=scope)
            plan = make_plan([app], Inventory([app]))
            self.assertIn(flag, plan.steps[0].argv)
            self.assertNotIn("--delete-data", plan.steps[0].argv)
            self.assertNotIn("-y", plan.steps[0].argv)

    def test_snap_keeps_normal_snapshot_behavior(self):
        app = App("snap:demo", "snap", "demo", "Demo", size_bytes=1000)
        with patch("app_remover.planning.capture", return_value="31d"):
            plan = make_plan([app], Inventory([app]))
        self.assertEqual(plan.steps[0].argv, ["sudo", "snap", "remove", "demo"])
        self.assertTrue(any("deshabilitadas" in note for note in plan.steps[0].notes))

    def test_appimage_uses_argv_and_trash(self):
        path = "/home/example/Demo $(touch SHOULD_NOT_EXIST).AppImage"
        app = App("appimage:" + path, "appimage", path, "Demo", paths=[path])
        with patch("app_remover.planning.shutil.which", return_value="/usr/bin/gio"):
            plan = make_plan([app], Inventory([app]))
        self.assertEqual(plan.steps[0].argv, ["gio", "trash", "--", path])
        self.assertEqual(plan.steps[0].estimated_bytes, 0)


class InventoryTests(unittest.TestCase):
    def test_apt_excludes_removed_records_and_marks_essential(self):
        output = (
            "demo\tinstalled\t1\t42\tno\tno\toptional\tDemo\n"
            "old\tconfig-files\t1\t10\tno\tno\toptional\tOld\n"
            "base\tinstalled\t1\t10\tyes\tno\trequired\tBase\n"
        )
        with patch("app_remover.inventory.capture", return_value=output):
            apps = apt_apps()
        self.assertEqual([app.identifier for app in apps], ["demo", "base"])
        self.assertEqual(apps[0].size_bytes, 42 * 1024)
        self.assertTrue(apps[1].protected)

    def test_malformed_apt_identifier_is_rejected(self):
        with patch(
            "app_remover.inventory.capture",
            return_value="--danger\tinstalled\t1\t42\tno\tno\toptional\tDemo\n",
        ):
            with self.assertRaises(Refusal):
                apt_apps()

    def test_flatpak_reads_explicit_scope_and_commit(self):
        with patch(
            "app_remover.inventory.capture",
            side_effect=["org.example.Demo/x86_64/stable\tDemo\tsystem\t10.0 MB\n", "abcdef\n"],
        ) as call:
            apps = flatpak_apps()
        self.assertEqual(apps[0].size_bytes, 10_000_000)
        self.assertEqual(apps[0].fingerprint, "abcdef")
        self.assertIn("--system", call.call_args.args[0])

    def test_malformed_flatpak_data_is_not_ignored(self):
        with patch("app_remover.inventory.capture", return_value="unexpected output"):
            with self.assertRaises(Refusal):
                flatpak_apps()

    def test_flatpak_identifier_cannot_be_a_native_option(self):
        with patch(
            "app_remover.inventory.capture",
            return_value="--danger/x86_64/stable\tDemo\tsystem\t10 MB",
        ):
            with self.assertRaises(Refusal):
                flatpak_apps()

    def test_snap_list_records_revision(self):
        with patch(
            "app_remover.inventory.capture",
            return_value="Name Version Rev Tracking Publisher Notes\ndemo 1.2 42 latest dev -\n",
        ):
            apps = snap_apps()
        self.assertEqual(apps[0].fingerprint, "42")

    def test_appimage_launcher_path_with_spaces(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / ".local/share"
            desktops = data / "applications"
            desktops.mkdir(parents=True)
            image = home / "My Demo.AppImage"
            image.write_text("dummy")
            launcher = desktops / "demo.desktop"
            launcher.write_text(f'[Desktop Entry]\nName=Demo\nExec=env FLAG=1 "{image}" %u\n')
            apps = appimage_apps(home, data)
            self.assertEqual(len(apps), 1)
            self.assertEqual(apps[0].paths, [str(image), str(launcher)])

    def test_appimage_symlinks_and_foreign_paths_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            images = home / "Applications"
            images.mkdir()
            (home / "source").write_text("dummy")
            (images / "Linked.AppImage").symlink_to(home / "source")
            self.assertEqual(appimage_apps(home, home / ".local/share"), [])
            with self.assertRaises(Refusal):
                appimage_apps(home, home / ".local/share", ["/tmp"])

    def test_only_valid_user_extension_uuid_is_inventoried(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / ".local/share"
            extension = data / "gnome-shell/extensions/demo@example.org"
            extension.mkdir(parents=True)
            meta = extension / "metadata.json"
            meta.write_text(json.dumps({"uuid": extension.name, "name": "Demo", "version": 1}))
            self.assertEqual(len(extension_apps(home, data)), 1)
            meta.write_text(json.dumps({"uuid": "--unsafe", "name": "Demo"}))
            self.assertEqual(extension_apps(home, data), [])

    def test_extension_uuid_cannot_be_a_native_option(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / ".local/share"
            extension = data / "gnome-shell/extensions/--unsafe"
            extension.mkdir(parents=True)
            (extension / "metadata.json").write_text(
                json.dumps({"uuid": "--unsafe", "name": "Demo"})
            )
            self.assertEqual(extension_apps(home, data), [])


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env = patch.dict(os.environ, {"XDG_STATE_HOME": self.temp.name})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.uid = patch("app_remover.execution.os.geteuid", return_value=1000)
        self.uid.start()
        self.addCleanup(self.uid.stop)
        self.app = flatpak()
        self.inventory = Inventory([self.app])
        self.plan = make_plan([self.app], self.inventory)

    def test_success_verifies_removal_and_private_report(self):
        snapshots = iter([self.inventory, Inventory()])
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0)

        path, report, code = execute(self.plan, lambda: next(snapshots), run)
        self.assertEqual(code, 0)
        self.assertEqual(report["verification"][0]["status"], "removed")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(calls), 1)
        self.assertEqual(json.loads(path.read_text())["status"], "complete")

    def test_changed_installation_blocks_before_execution(self):
        changed = flatpak()
        changed.fingerprint = "new-commit"
        with self.assertRaisesRegex(Refusal, "Cambió"), patch("subprocess.run") as run:
            execute(self.plan, lambda: Inventory([changed]))
        run.assert_not_called()

    def test_stale_missing_app_blocks(self):
        with self.assertRaisesRegex(Refusal, "inventario cambió"), patch("subprocess.run") as run:
            execute(self.plan, Inventory)
        run.assert_not_called()

    def test_first_failure_stops_other_backends(self):
        second = App("snap:demo", "snap", "demo", "Demo")
        inventory = Inventory([self.app, second])
        with patch("app_remover.planning.capture", return_value="31d"):
            plan = make_plan(inventory.apps, inventory)
        calls = []

        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 1)

        with (
            patch("app_remover.planning.capture", return_value="31d"),
            patch("app_remover.execution.capture", return_value="No snapshots found."),
        ):
            _, report, code = execute(plan, lambda: inventory, run)
        self.assertEqual(len(calls), 1)
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "incomplete")

    def test_unavailable_verification_is_unknown_not_removed(self):
        snapshots = iter([self.inventory, Inventory(errors={"flatpak": "timeout"})])
        _, report, code = execute(
            self.plan,
            lambda: next(snapshots),
            lambda argv, **kw: subprocess.CompletedProcess(argv, 0),
        )
        self.assertEqual(code, 1)
        self.assertEqual(report["verification"][0]["status"], "unknown")

    def test_interrupt_is_recorded(self):
        def run(*args, **kwargs):
            raise KeyboardInterrupt

        _, report, code = execute(self.plan, lambda: self.inventory, run)
        self.assertEqual(code, 130)
        self.assertEqual(report["status"], "interrupted")

    def test_audit_failure_prevents_mutation(self):
        with patch("app_remover.execution.report_file", side_effect=OSError("disk full")):
            with patch("subprocess.run") as run, self.assertRaises(OSError):
                execute(self.plan, lambda: self.inventory)
            run.assert_not_called()


class CLITests(unittest.TestCase):
    def test_json_plan_never_executes(self):
        app = flatpak()
        with (
            patch("app_remover.cli.discover", return_value=Inventory([app])),
            patch("app_remover.cli.execute") as execute_mock,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            code = main(["plan", "Demo", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["apps"][0]["key"], app.key)
        execute_mock.assert_not_called()

    def test_noninteractive_removal_cannot_be_piped_yes(self):
        with (
            patch("app_remover.cli.discover", return_value=Inventory([flatpak()])),
            patch("app_remover.cli.os.geteuid", return_value=1000),
            patch("app_remover.cli.sys.stdin.isatty", return_value=False),
            patch("app_remover.cli.execute") as execute_mock,
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            code = main(["remove", "Demo"])
        self.assertEqual(code, 2)
        execute_mock.assert_not_called()

    def test_cancel_at_confirmation_does_nothing(self):
        with (
            contextlib.redirect_stdout(io.StringIO()),
            patch("app_remover.cli.discover", return_value=Inventory([flatpak()])),
            patch("app_remover.cli.os.geteuid", return_value=1000),
            patch("app_remover.cli.sys.stdin.isatty", return_value=True),
            patch("app_remover.cli.sys.stdout.isatty", return_value=True),
            patch("builtins.input", return_value="no"),
            patch("app_remover.cli.execute") as execute_mock,
        ):
            code = main(["remove", "Demo"])
        self.assertEqual(code, 0)
        execute_mock.assert_not_called()

    def test_terminal_metadata_cannot_inject_escape_sequences(self):
        self.assertNotIn("\x1b", clean("Demo\x1b[2J\n"))

    def test_size_units_are_not_confused(self):
        self.assertEqual(parse_size("1.5 MiB"), 1572864)
        self.assertEqual(parse_size("1.5 MB"), 1500000)
        self.assertIsNone(parse_size("unknown"))
        self.assertEqual(flatpak_flag("system"), "--system")


if __name__ == "__main__":
    unittest.main()
