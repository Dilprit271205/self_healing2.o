# analysis/response_engine.py

import os
import psutil
from collections import defaultdict
from analysis.policy_engine import policy_engine


class ResponseEngine:
    """
    PPT + review aligned
    adaptive healing engine

    Slide 16–17

    Healing Flow:
    observe
    → restrict
    → isolate
    → block_resources
    → terminate
    → trust_recovery
    """

    def __init__(self, safe_mode=None):

        self.response_history = (
            defaultdict(list)
        )

        self.restricted_pids = set()
        self.isolated_pids = set()

        if safe_mode is None:
            self.safe_mode = os.getenv(
                "SELF_HEALING_SAFE_MODE",
                "false"
            ).lower() in (
                "1",
                "true",
                "yes",
                "y"
            )
        else:
            self.safe_mode = bool(safe_mode)
        # Protect the monitor/controller process and its parent from healing
        try:
            self.protected_pids = {
                os.getpid(),
                os.getppid(),
                1
            }
        except:
            self.protected_pids = set()

    def add_protected_pid(self, pid):
        try:
            self.protected_pids.add(int(pid))
        except:
            pass

    def _normalize_text(self, value):
        try:
            return str(value).lower()
        except Exception:
            return ""

    def _matches_safe_tokens(self, text, tokens):
        text = self._normalize_text(text)
        return any(token in text for token in tokens)

    def _is_hard_protected_pid(self, pid):
        try:
            return int(pid) in getattr(self, "protected_pids", set()) or int(pid) <= 10
        except Exception:
            return True

    def _can_override_name_protection(self, force=False):
        return bool(force)

    def _is_critical_process_hint(
        self,
        process_name="",
        cmdline="",
        exe_path=""
    ):
        return policy_engine.is_critical_process_hint({
            "name": process_name,
            "cmdline": cmdline,
            "exe": exe_path,
        })

    def _is_runtime_controller_process(
        self,
        process_name="",
        cmdline="",
        exe_path="",
        cwd=""
    ):
        text = " ".join([
            self._normalize_text(process_name),
            self._normalize_text(cmdline),
            self._normalize_text(exe_path),
            self._normalize_text(cwd),
        ])

        if (
            "streamlit" in text
            or "dashboard.py" in text
        ):
            return True

        if "main.py" not in text:
            return False

        controller_context = (
            "self_healing",
            "self-healing",
            "self_healing2",
            "healing\\self_healing",
            "healing/self_healing",
        )

        return any(
            token in text
            for token in controller_context
        )

    def _is_operator_control_process(
        self,
        process_name="",
        exe_path=""
    ):
        identity = " ".join([
            self._normalize_text(process_name),
            self._normalize_text(exe_path),
        ])

        operator_tokens = (
            "qterminal",
            "gnome-terminal",
            "xfce4-terminal",
            "konsole",
            "xterm",
            "bash",
            "zsh",
            "fish",
            "powershell",
            "pwsh",
            "cmd.exe",
            "wt.exe",
            "openconsole.exe",
            "conhost.exe",
        )

        return any(
            token in identity
            for token in operator_tokens
        )

    def _is_non_overridable_process(
        self,
        process_name="",
        cmdline="",
        exe_path="",
        cwd=""
    ):
        if self._is_critical_process_hint(
            process_name,
            cmdline,
            exe_path
        ):
            return True

        if self._is_operator_control_process(
            process_name,
            exe_path
        ):
            return True

        if self._is_runtime_controller_process(
            process_name,
            cmdline,
            exe_path,
            cwd
        ):
            return True

        category = policy_engine.infer_category({
            "name": process_name,
            "cmdline": cmdline,
            "exe": exe_path,
            "cwd": cwd,
        })

        return policy_engine.is_hard_protected_category(
            category
        )

    def is_protected_process(self, pid, process_name="", cmdline="", exe_path="", cwd=""):
        process_name = self._normalize_text(process_name)
        cmdline = self._normalize_text(cmdline)
        exe_path = self._normalize_text(exe_path)
        cwd = self._normalize_text(cwd)

        if self._is_hard_protected_pid(pid):
            return True

        if self._is_operator_control_process(
            process_name,
            exe_path
        ):
            return True

        if self._is_runtime_controller_process(
            process_name,
            cmdline,
            exe_path,
            cwd
        ):
            return True

        if self._is_critical_process_hint(
            process_name,
            cmdline,
            exe_path
        ):
            return True

        if self._is_non_overridable_process(
            process_name,
            cmdline,
            exe_path
        ):
            return True

        return False

    def _stage_rank(self, stage):
        order = {
            "observe": 0,
            "trust_recovery": 0,
            "restrict": 1,
            "throttle": 1,
            "isolate": 2,
            "quarantine": 2,
            "block_resources": 3,
            "terminate": 4
        }
        return order.get(stage, 0)

    def _cap_stage(self, stage, max_stage):
        if self._stage_rank(stage) <= self._stage_rank(max_stage):
            return stage

        return max_stage

    def _apply_false_positive_suppression(
        self,
        stage,
        process_info,
        persistence_state
    ):
        category = policy_engine.infer_category(
            process_info
        )

        if not policy_engine.is_suppressed_category(
            category
        ):
            return stage

        if persistence_state.get(
            "allow_disrupt_suppressed",
            False
        ):
            return stage

        if persistence_state.get(
            "catastrophic_ready",
            False
        ) and persistence_state.get(
            "force_terminate",
            False
        ):
            return self._cap_stage(
                stage,
                "throttle"
            )

        if persistence_state.get(
            "confirmed_behavior",
            False
        ):
            return self._cap_stage(
                stage,
                "throttle"
            )

        return "observe"

    # -----------------------------------------
    # PRIVILEGED ACTIONS (network / cgroup quarantine)
    # guarded by SELF_HEALING_ALLOW_PRIVILEGE env var
    # -----------------------------------------
    def _privileges_allowed(self):
        try:
            return os.getenv("SELF_HEALING_ALLOW_PRIVILEGE", "false").lower() in ("1", "true", "yes", "y")
        except:
            return False

    def network_quarantine(self, pid, ips=None):
        """Attempt to block network traffic to/from provided IPs using nftables.
        Returns a token that can be used for rollback, or None on failure/skip.
        """
        if not self._privileges_allowed():
            return None

        try:
            import subprocess
            # if IPs provided, try nft-based set + rule
            if ips:
                token = f"self_heal_blk_{pid}"
                cmd_create = ["/usr/sbin/nft", "add", "set", "inet", "filter", token, "{ type ipv4_addr; flags interval; }"]
                subprocess.run(cmd_create, check=False)
                for ip in ips:
                    cmd_add = ["/usr/sbin/nft", "add", "element", "inet", "filter", token, "{", ip, "}"]
                    subprocess.run(cmd_add, check=False)
                cmd_rule = ["/usr/sbin/nft", "add", "rule", "inet", "filter", "output", "ip", "daddr", "@", token, "drop"]
                subprocess.run(cmd_rule, check=False)
                return token

            # fallback: block by UID using iptables owner match
            proc = psutil.Process(pid)
            uid = proc.uids().real
            rule = ["/sbin/iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-j", "DROP"]
            subprocess.run(rule, check=False)
            return {"uid_rule": uid}
        except Exception:
            return None

    def network_quarantine_rollback(self, token):
        if not token:
            return
        if not self._privileges_allowed():
            return
        try:
            import subprocess
            if isinstance(token, dict) and token.get("uid_rule") is not None:
                uid = token["uid_rule"]
                subprocess.run(["/sbin/iptables", "-D", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-j", "DROP"], check=False)
            else:
                subprocess.run(["/usr/sbin/nft", "delete", "rule", "inet", "filter", "output", "handle", token], check=False)
                subprocess.run(["/usr/sbin/nft", "delete", "set", "inet", "filter", token], check=False)
        except Exception:
            pass

    def cgroup_quarantine(self, pid, cpu_shares=128, mem_limit_mb=128):
        """Attempt to create a systemd scope for the pid with resource limits.
        Returns the scope name or None.
        """
        if not self._privileges_allowed():
            return None
        try:
            import subprocess
            scope = f"self_heal_{pid}.scope"
            cmd = ["/usr/bin/systemd-run", "--unit", scope, "--scope", "--slice=machine.slice", "-p", f"CPUQuota={cpu_shares}%", "-p", f"MemoryMax={mem_limit_mb}M", "/bin/true"]
            subprocess.run(cmd, check=False)
            # then move pid into scope (best-effort)
            subprocess.run(["/usr/bin/systemd-run", "--unit", scope, "--scope", "bash", "-c", f"kill -STOP {pid} || true; kill -CONT {pid} || true"], check=False)
            return scope
        except Exception:
            return None

    def cgroup_quarantine_rollback(self, scope):
        if not scope:
            return
        if not self._privileges_allowed():
            return
        try:
            import subprocess
            subprocess.run(["/usr/bin/systemctl", "stop", scope], check=False)
            subprocess.run(["/usr/bin/systemctl", "disable", scope], check=False)
        except Exception:
            pass

    # -----------------------------------------
    # MAIN RESPONSE ROUTER
    # -----------------------------------------
    def execute(
        self,
        pid,
        process_info,
        persistence_state
    ):

        stage = persistence_state.get(
            "stage",
            "observe"
        )

        force_terminate = (
            stage == "terminate"
            and
            bool(
                persistence_state.get(
                    "force_terminate",
                    False
                )
            )
        )

        if stage == "terminate" and not (
            force_terminate
            or persistence_state.get("termination_ready")
            or persistence_state.get("catastrophic_ready")
        ):
            stage = "observe"

        result = {

            "pid": pid,
            "stage": stage,
            "action_taken": False,
            "status": "none"
        }

        try:

            # =====================================
            if self.safe_mode:

                return {

                    "pid":
                        pid,

                    "stage":
                        stage,

                    "action_taken":
                        False,

                    "status":
                        (
                            "safe mode "
                            "(healing disabled)"
                        )
                }

            # ---------------------------------
            # SAFE PROCESS FILTER
            # prevents accidental system instability
            # ---------------------------------
            process_name = (
                self._normalize_text(process_info.get(
                    "name",
                    ""
                ))
            )

            cmdline = (
                self._normalize_text(process_info.get(
                    "cmdline",
                    ""
                ))
            )

            exe_path = (
                self._normalize_text(process_info.get(
                    "exe",
                    ""
                ))
            )

            cwd = (
                self._normalize_text(process_info.get(
                    "cwd",
                    ""
                ))
            )

            stage = self._apply_false_positive_suppression(
                stage,
                process_info,
                persistence_state
            )
            result[
                "stage"
            ] = stage

            if (
                stage != "observe"
                and self._is_non_overridable_process(
                    process_name,
                    cmdline,
                    exe_path,
                    cwd
                )
            ):
                return {
                    "pid": pid,
                    "stage": "protected",
                    "action_taken": False,
                    "status": "hard protected process"
                }

            # Protect explicitly configured PIDs (monitor, parent, etc.)
            if (
                stage != "observe"
                and self._is_critical_process_hint(
                process_name,
                cmdline,
                exe_path
                )
            ):
                return {
                    "pid": pid,
                    "stage": "protected",
                    "action_taken": False,
                    "status": "critical process hint"
                }

            if (
                stage != "observe"
                and
                self.is_protected_process(pid, process_name, cmdline, exe_path)
                and
                not self._can_override_name_protection(force_terminate)
            ):
                return {
                    "pid": pid,
                    "stage": "protected",
                    "action_taken": False,
                    "status": "protected pid"
                }

            # ---------------------------------
            # OBSERVE
            # ---------------------------------
            if stage == "observe":

                result[
                    "status"
                ] = (
                    "monitoring"
                )

            # ---------------------------------
            # RESTRICT
            # CPU throttling
            # ---------------------------------
            elif (
                stage
                in {"restrict", "throttle"}
            ):

                result = (
                    self.restrict_process(
                        pid,
                        stage="throttle"
                    )
                )

            # ---------------------------------
            # ISOLATE
            # suspend process
            # ---------------------------------
            elif (
                stage
                in {"isolate", "quarantine"}
            ):

                result = (
                    self.isolate_process(
                        pid,
                        stage="quarantine"
                    )
                )

            # ---------------------------------
            # BLOCK RESOURCES
            # stronger than isolate
            # ---------------------------------
            elif (
                stage
                ==
                "block_resources"
            ):

                result = (
                    self.block_resources(
                        pid
                    )
                )

            # ---------------------------------
            # TERMINATE
            # ---------------------------------
            elif (
                stage
                == "terminate"
            ):

                net_token = None
                scope = None

                try:
                    net_token = self.network_quarantine(pid)
                except:
                    net_token = None

                try:
                    scope = self.cgroup_quarantine(pid)
                except:
                    scope = None

                result = (
                    self.terminate_process(
                        pid,
                        force=force_terminate,
                        process_info=process_info,
                        kill_family=bool(
                            persistence_state.get(
                                "kill_family",
                                False
                            )
                        )
                    )
                )

                # rollback quarantine resources
                try:
                    if net_token:
                        self.network_quarantine_rollback(net_token)
                except:
                    pass

                try:
                    if scope:
                        self.cgroup_quarantine_rollback(scope)
                except:
                    pass

            # ---------------------------------
            # TRUST RECOVERY
            # slide 17
            # ---------------------------------
            elif (
                stage
                ==
                "trust_recovery"
            ):

                result = (
                    self.resume_process(
                        pid
                    )
                )

            self.response_history[
                pid
            ].append(
                result
            )

            return result

        except Exception as e:

            return {

                "pid":
                    pid,

                "stage":
                    stage,

                "action_taken":
                    False,

                "status":
                    f"error: {e}"
            }
    # -----------------------------------------
    # RESTRICT
    # lower CPU impact
    # -----------------------------------------
    def restrict_process(
        self,
        pid,
        stage="restrict"
    ):

        try:

            proc = psutil.Process(
                pid
            )

            # lower priority
            proc.nice(10)

            # reduce CPU affinity
            try:

                cpu_count = len(
                    proc.cpu_affinity()
                )

                if cpu_count > 1:

                    proc.cpu_affinity(
                        [0]
                    )

            except:
                pass

            self.restricted_pids.add(
                pid
            )

            return {

                "pid":
                    pid,

                "stage":
                    stage,

                "action_taken":
                    True,

                "status":
                    (
                        "priority throttled"
                    )
            }

        except Exception as e:

            return {

                "pid":
                    pid,

                "stage":
                    stage,

                "action_taken":
                    False,

                "status":
                    str(e)
            }

    # -----------------------------------------
    # ISOLATE
    # pause execution only
    # -----------------------------------------
    def isolate_process(
        self,
        pid,
        stage="isolate"
    ):

        try:

            proc = psutil.Process(
                pid
            )

            proc.suspend()

            self.isolated_pids.add(
                pid
            )

            return {

                "pid":
                    pid,

                "stage":
                    stage,

                "action_taken":
                    True,

                "status":
                    "temporarily isolated"
            }

        except Exception as e:

            return {

                "pid":
                    pid,

                "stage":
                    stage,

                "action_taken":
                    False,

                "status":
                    str(e)
            }

    # -----------------------------------------
    # BLOCK RESOURCES
    # stronger containment
    # -----------------------------------------
    def block_resources(
        self,
        pid
    ):

        try:

            proc = psutil.Process(
                pid
            )

            # hard throttle
            proc.nice(19)

            # limit CPU
            try:
                proc.cpu_affinity([0])
            except:
                pass

            # suspend children
            for child in proc.children(
                recursive=True
            ):

                try:
                    child_name = self._normalize_text(child.name())
                    try:
                        child_cmd = " ".join(child.cmdline())
                    except Exception:
                        child_cmd = ""
                    child_exe = self._normalize_text(
                        child.exe() if hasattr(child, "exe") else ""
                    )

                    if self.is_protected_process(
                        child.pid,
                        child_name,
                        child_cmd,
                        child_exe
                    ):
                        continue

                    child.suspend()
                except:
                    pass

            return {

                "pid":
                    pid,

                "stage":
                    (
                        "block_resources"
                    ),

                "action_taken":
                    True,

                "status":
                    (
                        "resource restricted"
                    )
            }

        except Exception as e:

            return {

                "pid":
                    pid,

                "stage":
                    (
                        "block_resources"
                    ),

                "action_taken":
                    False,

                "status":
                    str(e)
            }

    # -----------------------------------------
    # TERMINATE
    # worm tree kill
    # -----------------------------------------
    def terminate_process(
        self,
        pid,
        force=False,
        process_info=None,
        kill_family=False
    ):

        try:
            process_info = process_info or {}

            try:
                proc = psutil.Process(
                    pid
                )
            except psutil.NoSuchProcess:
                related = self._processes_from_observed_pids(
                    process_info,
                    force=force
                )
                related.extend(
                    self._find_related_family_processes(
                    pid,
                    self._normalize_text(
                        process_info.get(
                            "name",
                            ""
                        )
                    ),
                    self._normalize_text(
                        process_info.get(
                            "cmdline",
                            ""
                        )
                    ),
                    self._normalize_text(
                        process_info.get(
                            "exe",
                            ""
                        )
                    ),
                    process_info,
                    force=force,
                    enabled=kill_family
                    )
                )

                return self._terminate_targets(
                    pid,
                    related,
                    status_prefix="root exited; terminated related targets"
                )

            print(f"[ResponseEngine] Attempting termination: pid={pid}")

            try:
                proc_name = self._normalize_text(proc.name())
            except Exception:
                proc_name = ""

            try:
                proc_cmdline = " ".join(proc.cmdline())
            except Exception:
                proc_cmdline = ""

            try:
                proc_exe = self._normalize_text(proc.exe())
            except Exception:
                proc_exe = ""

            try:
                proc_cwd = self._normalize_text(proc.cwd())
            except Exception:
                proc_cwd = self._normalize_text(
                    (process_info or {}).get(
                        "cwd",
                        ""
                    )
                )

            if self._is_hard_protected_pid(pid):
                return {
                    "pid": pid,
                    "stage": "terminate",
                    "action_taken": False,
                    "status": "hard protected pid - not terminated"
                }

            if self._is_non_overridable_process(
                proc_name,
                proc_cmdline,
                proc_exe,
                proc_cwd
            ):
                return {
                    "pid": pid,
                    "stage": "terminate",
                    "action_taken": False,
                    "status": "hard protected process - not terminated"
                }

            if (
                self.is_protected_process(
                pid,
                proc_name,
                proc_cmdline,
                proc_exe
                )
                and
                not self._can_override_name_protection(force)
            ):
                return {
                    "pid": pid,
                    "stage": "terminate",
                    "action_taken": False,
                    "status": "protected pid - not terminated"
                }

            children = proc.children(recursive=True)

            try:
                MAX_SAFE_KILL = int(os.getenv("SELF_HEALING_MAX_SAFE_KILL", "300"))
            except:
                MAX_SAFE_KILL = 300

            try:
                MAX_FORCE_KILL = int(os.getenv("SELF_HEALING_MAX_FORCE_KILL", "2000"))
            except:
                MAX_FORCE_KILL = 2000

            if len(children) > MAX_FORCE_KILL:
                return {
                    "pid": pid,
                    "stage": "block_resources",
                    "action_taken": False,
                    "status": (
                        "process tree exceeds forced termination ceiling"
                    )
                }

            if len(children) > MAX_SAFE_KILL and not force:
                return {
                    "pid": pid,
                    "stage": "block_resources",
                    "action_taken": False,
                    "status": (
                        "too many child processes, escalate to block_resources"
                    )
                }

            kill_targets = []
            seen_targets = set()

            def add_target(target):
                try:
                    target_pid = int(target.pid)
                except Exception:
                    return

                if target_pid in seen_targets:
                    return

                seen_targets.add(
                    target_pid
                )
                kill_targets.append(
                    target
                )

            for observed in self._processes_from_observed_pids(
                process_info,
                force=force
            ):
                add_target(
                    observed
                )

            for related in self._find_related_family_processes(
                pid,
                proc_name,
                proc_cmdline,
                proc_exe,
                process_info,
                force=force,
                enabled=kill_family
            ):
                add_target(
                    related
                )

            for child in children:
                try:
                    child_name = self._normalize_text(child.name())
                    try:
                        child_cmd = " ".join(child.cmdline())
                    except Exception:
                        child_cmd = ""
                    child_exe = self._normalize_text(
                        child.exe() if hasattr(child, "exe") else ""
                    )
                    try:
                        child_cwd = self._normalize_text(child.cwd())
                    except Exception:
                        child_cwd = ""

                    if self._is_hard_protected_pid(child.pid):
                        continue

                    if self._is_non_overridable_process(
                        child_name,
                        child_cmd,
                        child_exe,
                        child_cwd
                    ):
                        continue

                    if (
                        self.is_protected_process(
                        child.pid,
                        child_name,
                        child_cmd,
                        child_exe
                        )
                        and
                        not self._can_override_name_protection(force)
                    ):
                        continue

                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        continue
                    except:
                        pass

                    add_target(child)
                except Exception:
                    pass

            try:
                proc.terminate()
                add_target(proc)
            except psutil.NoSuchProcess:
                pass
            except:
                pass

            for target in list(kill_targets):
                if target.pid == pid:
                    continue

                try:
                    target.terminate()
                except psutil.NoSuchProcess:
                    continue
                except Exception:
                    pass

            gone, alive = psutil.wait_procs(kill_targets, timeout=3)

            if alive:
                for p in alive:
                    try:
                        p.kill()
                    except psutil.NoSuchProcess:
                        continue
                    except:
                        pass

                gone2, alive2 = psutil.wait_procs(alive, timeout=2)
                gone = gone + gone2

                if alive2:
                    alive_pids = [p.pid for p in alive2 if p is not None]
                    return {
                        "pid": pid,
                        "stage": "terminate",
                        "action_taken": bool(gone),
                        "status": (
                            "partial termination, alive pids=" f"{alive_pids}"
                        ),
                    }

            return {
                "pid": pid,
                "stage": "terminate",
                "action_taken": bool(gone),
                "status": f"terminated targets={len(gone)}",
            }

        except Exception as e:

            return {

                "pid":
                    pid,

                "stage":
                    "terminate",

                "action_taken":
                    False,

                "status":
                    str(e)
            }

    def _processes_from_observed_pids(
        self,
        process_info,
        force=False
    ):
        observed = []

        for observed_pid in (
            process_info.get(
                "observed_family_pids",
                []
            )
            or []
        ):
            try:
                observed_pid = int(
                    observed_pid
                )

                if self._is_hard_protected_pid(
                    observed_pid
                ):
                    continue

                candidate = psutil.Process(
                    observed_pid
                )

                try:
                    name = self._normalize_text(
                        candidate.name()
                    )
                except Exception:
                    name = ""

                try:
                    cmdline = self._normalize_text(
                        " ".join(
                            candidate.cmdline()
                        )
                    )
                except Exception:
                    cmdline = ""

                try:
                    exe = self._normalize_text(
                        candidate.exe()
                    )
                except Exception:
                    exe = ""

                try:
                    cwd = self._normalize_text(
                        candidate.cwd()
                    )
                except Exception:
                    cwd = ""

                if self._is_non_overridable_process(
                    name,
                    cmdline,
                    exe,
                    cwd
                ):
                    continue

                if (
                    self.is_protected_process(
                        observed_pid,
                        name,
                        cmdline,
                        exe,
                        cwd
                    )
                    and not self._can_override_name_protection(
                        force
                    )
                ):
                    continue

                observed.append(
                    candidate
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue
            except Exception:
                continue

        return observed

    def _terminate_targets(
        self,
        pid,
        targets,
        status_prefix="terminated targets"
    ):
        kill_targets = []
        seen = set()

        for target in targets or []:
            try:
                target_pid = int(
                    target.pid
                )
            except Exception:
                continue

            if target_pid in seen:
                continue

            seen.add(
                target_pid
            )
            kill_targets.append(
                target
            )

        if not kill_targets:
            return {
                "pid": pid,
                "stage": "terminate",
                "action_taken": False,
                "status": "No such process and no related family targets"
            }

        for target in list(
            kill_targets
        ):
            try:
                target.terminate()
            except psutil.NoSuchProcess:
                continue
            except Exception:
                pass

        gone, alive = psutil.wait_procs(
            kill_targets,
            timeout=1.5
        )

        if alive:
            for target in alive:
                try:
                    target.kill()
                except psutil.NoSuchProcess:
                    continue
                except Exception:
                    pass

            gone2, alive2 = psutil.wait_procs(
                alive,
                timeout=1
            )
            gone = gone + gone2
        else:
            alive2 = []

        return {
            "pid": pid,
            "stage": "terminate",
            "action_taken": bool(gone),
            "status": (
                f"{status_prefix}={len(gone)}"
                if not alive2
                else
                f"{status_prefix}={len(gone)} alive={[p.pid for p in alive2]}"
            )
        }

    # -----------------------------------------
    # TRUST RECOVERY
    # slide 17
    # -----------------------------------------
    def resume_process(
        self,
        pid
    ):

        try:

            proc = psutil.Process(
                pid
            )

            proc.resume()

            return {

                "pid":
                    pid,

                "stage":
                    "trust_recovery",

                "action_taken":
                    True,

                "status":
                    "process resumed"
            }

        except Exception as e:

            return {

                "pid":
                    pid,

                "stage":
                    "trust_recovery",

                "action_taken":
                    False,

                "status":
                    str(e)
            }

    def _find_related_family_processes(
        self,
        pid,
        proc_name,
        proc_cmdline,
        proc_exe,
        process_info,
        force=False,
        enabled=False
    ):
        if not (
            enabled
            and force
        ):
            return []

        try:
            target_cwd = self._normalize_text(
                process_info.get(
                    "cwd",
                    ""
                )
            )
            target_cmdline = self._normalize_text(
                process_info.get(
                    "cmdline",
                    proc_cmdline
                )
            )
            target_name = self._normalize_text(
                process_info.get(
                    "name",
                    proc_name
                )
            )
            target_exe = self._normalize_text(
                process_info.get(
                    "exe",
                    proc_exe
                )
            )

            if not (
                target_cmdline
                or target_cwd
            ):
                return []

            try:
                max_family = int(
                    os.getenv(
                        "SELF_HEALING_MAX_FAMILY_KILL",
                        "500"
                    )
                )
            except Exception:
                max_family = 500

            related = []

            for candidate in psutil.process_iter([
                "pid",
                "name",
                "exe",
                "cmdline",
                "cwd",
                "create_time"
            ]):
                try:
                    candidate_pid = int(
                        candidate.info.get(
                            "pid"
                        )
                    )

                    if candidate_pid == int(pid):
                        continue

                    if self._is_hard_protected_pid(
                        candidate_pid
                    ):
                        continue

                    candidate_name = self._normalize_text(
                        candidate.info.get(
                            "name",
                            ""
                        )
                    )
                    candidate_cmdline = self._normalize_text(
                        " ".join(
                            candidate.info.get(
                                "cmdline"
                            )
                            or []
                        )
                    )
                    candidate_exe = self._normalize_text(
                        candidate.info.get(
                            "exe",
                            ""
                        )
                    )
                    candidate_cwd = self._normalize_text(
                        candidate.info.get(
                            "cwd",
                            ""
                        )
                    )

                    if self._is_non_overridable_process(
                        candidate_name,
                        candidate_cmdline,
                        candidate_exe,
                        candidate_cwd
                    ):
                        continue

                    if (
                        self.is_protected_process(
                            candidate_pid,
                            candidate_name,
                            candidate_cmdline,
                            candidate_exe
                        )
                        and not self._can_override_name_protection(
                            force
                        )
                    ):
                        continue

                    same_cwd = (
                        bool(target_cwd)
                        and candidate_cwd == target_cwd
                    )
                    same_exe = (
                        bool(target_exe)
                        and candidate_exe == target_exe
                    ) or (
                        bool(target_name)
                        and candidate_name == target_name
                    )
                    same_command = (
                        bool(target_cmdline)
                        and candidate_cmdline == target_cmdline
                    )

                    if (
                        same_cwd
                        and same_exe
                        and (
                            same_command
                            or force
                        )
                    ):
                        related.append(
                            candidate
                        )

                    if len(related) >= max_family:
                        break

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess
                ):
                    continue
                except Exception:
                    continue

            return related

        except Exception:
            return []
