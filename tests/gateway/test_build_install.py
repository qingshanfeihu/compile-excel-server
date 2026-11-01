"""build_install：照 InfoTest 用框架自己的升级用例给床上每台设备装构建（带 test_build），请求协议与结果读取同 case_submit。"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import time

from gateway import framework, prune

from test_gateway import ALICE, _lease, _wait_done

# Like the framework: one report session per pytest run (log_path is set once per session), one directory per case
# under the staged path's mirror, a closing banner, and a result row whose url carries the owned report path.
FAKE_UPGRADE = '''
import json, os, time
from pathlib import Path


def test_upgrade(request):
    here = Path(__file__).resolve().parent
    root = Path(os.getcwd())
    case = Path(__file__).stem
    build = request.config.getoption("--build")
    image = os.environ.get("test_build", "nosuchbuild")
    verdicts = json.loads((root / "fake_verdicts.json").read_text()) if (root / "fake_verdicts.json").exists() else {}
    run = os.environ.setdefault("FAKE_LOG_PATH", "run-%d-%s" % (time.time_ns(), build))
    task, module = here.parent.name, here.parent.parent.name
    rel = "report/%s/%s/%s/%s/%s" % (run, module, task, here.name, case)
    (root / rel).mkdir(parents=True, exist_ok=True)
    result = str(verdicts.get(case, "PASS")).upper()
    (root / rel / (case + ".txt")).write_text(
        "target image %s on %s\\n######################      %s      ####################\\n#######   end case: %s\\n"
        % (image, build, result, case))
    rows = json.loads((root / "fake_results.json").read_text()) if (root / "fake_results.json").exists() else []
    rows.append({"table": build, "case_id": case, "sub_module": task, "result": verdicts.get(case, "PASS"),
                 "url": "http://jumphost/test/fw/" + rel + "/"})
    (root / "fake_results.json").write_text(json.dumps(rows))
'''

BUILD = "Beta_SYN-K_1_2_0_7"
IMAGE = "brandOS-Beta_SYN-K_1_2_0_7.click"
_sequences = itertools.count(1)


def _upgrade_cases(apv):
    folder = apv / "smoke_test" / "system" / "upgrade"
    folder.mkdir(parents=True, exist_ok=True)
    for case in ("999999990", "999999991", "999999992"):
        (folder / f"{case}.py").write_text(FAKE_UPGRADE, encoding="utf-8")
    return folder


def _request(**fields):
    body = {"schema": "bed-install@1", "build": BUILD, "image": IMAGE, **fields}
    return base64.b64encode(json.dumps(body).encode()).decode()


def _install(gw, lease, payload, request_id=None):
    sequence = next(_sequences)
    return gw.call(ALICE, "build_install", {**lease, "install_b64": payload,
                                            "request_id": request_id or f"install:{sequence}",
                                            "dispatch_sequence": sequence, "sequence_scope": "synthetic-executor"})


def test_build_install_runs_the_framework_upgrade_case_of_every_device_with_test_build(fake_env):
    gw = fake_env["gateway"]
    folder = _upgrade_cases(fake_env["apv"])
    payload = _request()
    submitted = _install(gw, _lease(gw), payload)
    assert submitted["ok"], submitted
    # The bed conf lists two devices: the first two declared upgrade cases, nothing for the third.
    assert submitted["case_ids"] == ["999999990", "999999991"]
    assert submitted["image"] == IMAGE and submitted["build"] == BUILD
    assert submitted["target_version"] == "Beta.SYN-K.1.2.0.7"
    assert submitted["sha256"] == hashlib.sha256(base64.b64decode(payload)).hexdigest()
    framework_shas = {case: hashlib.sha256((folder / f"{case}.py").read_bytes()).hexdigest()
                      for case in submitted["case_ids"]}
    assert {row["case_id"]: row["sha256"] for row in submitted["cases"]} == framework_shas
    staged = gw.cfg.staging_parent / submitted["task_id"] / framework.INSTALL_DIR
    assert sorted(path.name for path in staged.iterdir()) == ["999999990.py", "999999991.py", "install.json"]
    runner = (gw.cfg.state_dir / "tasks" / f"{submitted['task_id']}.sh").read_text(encoding="utf-8")
    assert f"export test_build={IMAGE}" in runner

    done = _wait_done(gw, ALICE, submitted["task_id"])
    assert done["rc"] == 0, done
    results = gw.call(ALICE, "case_results", {"task_id": submitted["task_id"]})
    assert results["ok"] and results["complete"] and results["channel"] == "ready", results
    assert results["ownership"] == "staging_directory" and results["module"] == "install"
    assert results["xlsx_sha256"] == submitted["sha256"]
    assert [(case["case_id"], case["result"]) for case in results["cases"]] == [("999999990", "PASS"), ("999999991", "PASS")]
    # The image reached the cases through test_build, as InfoTest's scheduler passes it.
    assert all(f"target image {IMAGE}" in case["log"] for case in results["cases"])


def test_a_failed_upgrade_case_reports_fail_with_its_log_and_sessions(fake_env):
    gw = fake_env["gateway"]
    folder = _upgrade_cases(fake_env["apv"])
    (fake_env["apv"] / "fake_verdicts.json").write_text(json.dumps({"999999991": "FAIL"}), encoding="utf-8")
    submitted = _install(gw, _lease(gw), _request())
    assert submitted["ok"], submitted
    _wait_done(gw, ALICE, submitted["task_id"])
    results = gw.call(ALICE, "case_results", {"task_id": submitted["task_id"]})
    by_case = {case["case_id"]: case for case in results["cases"]}
    assert by_case["999999990"]["result"] == "PASS" and "sessions" not in by_case["999999990"]
    assert by_case["999999991"]["result"] == "FAIL" and "end case: 999999991" in by_case["999999991"]["log"]
    assert by_case["999999991"]["sessions"] == {}
    assert folder.is_dir()


def test_an_inconsistent_install_request_is_refused_at_admission_without_touching_the_bed(fake_env):
    gw = fake_env["gateway"]
    _upgrade_cases(fake_env["apv"])
    lease = _lease(gw)
    for payload, reason in (
        (_request(image="brandOS-Beta_SYN-K_1_2_0_8.click"), "installs Beta.SYN-K.1.2.0.8"),
        (_request(image="Beta_SYN-K_1_2_0_7.iso"), "image must be an image file name"),
        (_request(image="../brandOS-Beta_SYN-K_1_2_0_7.click"), "image must be an image file name"),
        (_request(extra=True), "exactly"),
        (base64.b64encode(b"not json").decode(), "not base64 of a UTF-8 JSON request"),
    ):
        refused = _install(gw, lease, payload)
        assert not refused["ok"] and reason in refused["error"], refused
        assert refused["stage"] == "admission" and refused["reached_device"] is False
        assert refused["request_record"] == "recorded"
    assert not list(gw.cfg.staging_parent.glob(f"cex_*/{framework.INSTALL_DIR}"))
    assert not gw.state.bed_busy()


def test_every_conf_device_needs_a_declared_upgrade_case(fake_env):
    gw = fake_env["gateway"]
    folder = _upgrade_cases(fake_env["apv"])
    (folder / "999999991.py").unlink()
    refused = _install(gw, _lease(gw), _request())
    assert not refused["ok"] and "upgrade case 999999991" in refused["error"], refused
    assert refused["stage"] == "precheck" and refused["reached_device"] is False


def test_a_repeated_install_request_is_never_launched_twice(fake_env):
    gw = fake_env["gateway"]
    _upgrade_cases(fake_env["apv"])
    lease = _lease(gw)
    payload = _request()
    first = _install(gw, lease, payload, request_id="install:once")
    assert first["ok"], first
    _wait_done(gw, ALICE, first["task_id"])
    again = gw.call(ALICE, "build_install", {**lease, "install_b64": payload, "request_id": "install:once",
                                             "dispatch_sequence": next(_sequences), "sequence_scope": "synthetic-executor"})
    assert not again["ok"] and again["stage"] in ("duplicate", "admission"), again
    queried = gw.call(ALICE, "case_request", {"request_id": "install:once"})
    assert queried["found"] and queried["state"] == "started" and queried["task_id"] == first["task_id"], queried
    assert len(list(gw.cfg.staging_parent.glob(f"cex_*/{framework.INSTALL_DIR}"))) == 1


def test_gc_claims_old_install_staging_and_reports(fake_env):
    gw = fake_env["gateway"]
    _upgrade_cases(fake_env["apv"])
    submitted = _install(gw, _lease(gw), _request())
    assert submitted["ok"], submitted
    _wait_done(gw, ALICE, submitted["task_id"])
    later = time.time() + 30 * 86400
    plan = prune.collect(gw.cfg, 7, now=later)
    staged = gw.cfg.staging_parent / submitted["task_id"] / framework.INSTALL_DIR
    reports = list((fake_env["apv"] / "report").glob(f"*/*/{submitted['task_id']}/{framework.INSTALL_DIR}"))
    assert len(reports) == 1
    # The request journal protects a task whose request is not collected yet, as for workbooks.
    protected = submitted["task_id"] in gw.state.protected_request_tasks()
    assert (staged in plan["staging"]) is not protected and (reports[0] in plan["reports"]) is not protected
    assert os.path.isdir(staged)
