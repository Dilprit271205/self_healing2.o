# analysis/response_engine.py

import os
import psutil
from collections import defaultdict


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

    def add_protected_pid(self, pid):
        try:
            self.protected_pids.add(int(pid))
        except:
            pass

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
                process_info.get(
                    "name",
                    ""
                ).lower()
            )

            cmdline = (
                process_info.get(
                    "cmdline",
                    ""
                ).lower()
            )

            exe_path = (
                process_info.get(
                    "exe",
                    ""
                ).lower()
            )

            # Protect explicitly configured PIDs (monitor, parent, etc.)
            if pid in getattr(self, "protected_pids", set()):

                return {

                    "pid":
                        pid,

                    "stage":
                        "protected",

                    "action_taken":
                        False,

                    "status":
                        "protected pid"
                }

            system_safe = [

                "systemd",
                "init",
                "kernel",
                "explorer.exe",
                "svchost.exe",

                # Linux desktop safety
                "gnome-shell",
                "xorg",
                "kde",
                "plasmashell",

                # terminal / shell safety
                "bash",
                "zsh",
                "sh",
                "fish",
                "tmux",
                "screen",
                "xterm",
                "gnome-terminal",
                "konsole",
                "terminator",
                "tilix",
                "kitty",
                "alacritty",
                "wezterm",
                "hyper",
                "lxterminal",

                # browser safety
                "chrome",
                "google-chrome",
                "chromium",
                "chrome-wrapper",
                "chrome_sandbox",
                "firefox",
                "brave",
                "msedge",
                "opera",
                "vivaldi",

                # dev tools
                "code",
                "streamlit",
                "jupyter",
                "notebook"
            ]

            safe_cmd_keywords = [
                "dashboard.py",
                "dashboard_v1",
                "dashboard_v1_backup.py",
                "streamlit",
                "jupyter",
                "notebook",
                "main.py"
            ]

            terminal_safe_cmd_keywords = [
                "vscode-server",
                "code-server",
                "jetbrains",
                "pycharm",
                "terminal",
                "gnome-terminal",
                "konsole",
                "alacritty",
                "wezterm",
                "kitty"
            ]

            safe_shell_names = [
                "bash",
                "zsh",
                "sh",
                "fish",
                "tmux",
                "screen"
            ]

            if (
                any(keyword in process_name for keyword in system_safe)
                or
                any(keyword in process_name for keyword in safe_shell_names)
                or
                any(keyword in cmdline for keyword in safe_cmd_keywords)
                or
                any(keyword in exe_path for keyword in safe_cmd_keywords)
                or
                any(keyword in cmdline for keyword in terminal_safe_cmd_keywords)
            ):

                return {

                    "pid":
                        pid,

                    "stage":
                        "protected",

                    "action_taken":
                        False,

                    "status":
                        "trusted process"
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
                == "restrict"
            ):

                result = (
                    self.restrict_process(
                        pid
                    )
                )

            # ---------------------------------
            # ISOLATE
            # suspend process
            # ---------------------------------
            elif (
                stage
                == "isolate"
            ):

                result = (
                    self.isolate_process(
                        pid
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
                        pid
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
        pid
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
                    "restrict",

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
                    "restrict",

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
        pid
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
                    "isolate",

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
                    "isolate",

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
        pid
    ):

        try:

            proc = psutil.Process(
                pid
            )

            print(f"[ResponseEngine] Attempting termination: pid={pid}")

            # Protect monitor and parent from being killed
            if pid in getattr(self, "protected_pids", set()):
                return {
                    "pid": pid,
                    "stage": "terminate",
                    "action_taken": False,
                    "status": "protected pid - not terminated"
                }

            # Limit the number of children to kill at once to avoid resource storms
            children = proc.children(recursive=True)

            # Safety: do not attempt destructive kills for extremely large trees
            try:
                MAX_SAFE_KILL = int(os.getenv("SELF_HEALING_MAX_SAFE_KILL", "300"))
            except:
                MAX_SAFE_KILL = 300

            if len(children) > MAX_SAFE_KILL:
                return {
                    "pid": pid,
                    "stage": "block_resources",
                    "action_taken": False,
                    "status": (
                        "too many child processes, escalate to block_resources"
                    )
                }

            kill_targets = []

            # Prefer graceful terminate, then escalate to kill if needed
            for child in children:
                try:
                    if child.pid in getattr(self, "protected_pids", set()):
                        continue

                    try:
                        c_cmd = " ".join(child.cmdline())
                        if "main.py" in c_cmd:
                            continue
                    except:
                        pass

                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        continue
                    except:
                        pass

                    kill_targets.append(child)
                except Exception:
                    pass

            # also terminate parent after children
            try:
                proc.terminate()
                kill_targets.append(proc)
            except psutil.NoSuchProcess:
                pass
            except:
                pass

            gone, alive = psutil.wait_procs(kill_targets, timeout=3)

            # escalate remaining alive to kill
            if alive:
                for p in alive:
                    try:
                        p.kill()
                    except psutil.NoSuchProcess:
                        continue
                    except:
                        pass

                gone2, alive2 = psutil.wait_procs(alive, timeout=2)

                if alive2:
                    alive_pids = [p.pid for p in alive2 if p is not None]
                    return {
                        "pid": pid,
                        "stage": "terminate",
                        "action_taken": bool(gone or gone2),
                        "status": (
                            "partial termination, alive pids=" f"{alive_pids}"
                        ),
                    }

            return {
                "pid": pid,
                "stage": "terminate",
                "action_taken": bool(gone),
                "status": "terminated",
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