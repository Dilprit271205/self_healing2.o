# analysis/response_engine.py

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

    def __init__(self):

        self.response_history = (
            defaultdict(list)
        )

        self.restricted_pids = set()
        self.isolated_pids = set()

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
        # enable actual healing now so
        # worm termination can occur automatically.
        # =====================================
        SAFE_MODE = False

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
            # disables actual healing
            # =====================================
            if SAFE_MODE:

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
            # prevents accidental
            # system instability
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
                "notebook"
            ]

            if (
                any(keyword in process_name for keyword in system_safe)
                or
                any(keyword in cmdline for keyword in safe_cmd_keywords)
                or
                any(keyword in exe_path for keyword in safe_cmd_keywords)
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

            children = proc.children(
                recursive=True
            )

            for child in children:

                try:
                    child.kill()
                except:
                    pass

            proc.kill()

            return {

                "pid":
                    pid,

                "stage":
                    "terminate",

                "action_taken":
                    True,

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