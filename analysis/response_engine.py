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
        # Protect the monitor/controller process and its parent from healing
        try:
            self.protected_pids = {
                os.getpid(),
                os.getppid()
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
    # MAIN RESPONSE ROUTER
    # -----------------------------------------
    def execute(
        self,
        pid,
        process_info,
        persistence_state
    ):

        # =====================================
        # SAFE MODE
        # disable actual healing only when explicitly configured
        # =====================================
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
            # SAFE TEST MODE
            # disables actual healing unless explicitly enabled
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

                result = (
                    self.terminate_process(
                        pid
                    )
                )

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

            max_kill = 200
            kill_targets = []

            for i, child in enumerate(children):

                if i >= max_kill:
                    break

                try:
                    # skip protected pids
                    if child.pid in getattr(self, "protected_pids", set()):
                        continue

                    # skip children whose cmdline indicates the monitor/controller
                    try:
                        c_cmd = " ".join(child.cmdline())
                        if "main.py" in c_cmd:
                            continue
                    except:
                        pass

                    child.kill()
                    kill_targets.append(child)
                except psutil.NoSuchProcess:
                    pass
                except:
                    pass

            try:
                proc.kill()
                kill_targets.append(proc)
            except psutil.NoSuchProcess:
                pass
            except:
                pass

            gone, alive = psutil.wait_procs(
                kill_targets,
                timeout=3
            )

            if alive:
                alive_pids = [p.pid for p in alive if p is not None]
                return {

                    "pid":
                        pid,

                    "stage":
                        "terminate",

                    "action_taken":
                        bool(gone),

                    "status":
                        (
                            "partial termination, alive pids="
                            f"{alive_pids}"
                        )
                }

            return {

                "pid":
                    pid,

                "stage":
                    "terminate",

                "action_taken":
                    bool(gone),

                "status":
                    "terminated"
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