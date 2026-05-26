# analysis/trust/trust_vector.py

trust_db = {}


# ---------------------------------------------------
# DEFAULT TRUST STATE
# ---------------------------------------------------
def default_trust_state():

    return {

        # -----------------------------------------
        # Dynamic trust vectors
        # PPT behavioral trust
        # -----------------------------------------
        "cpu": 1.0,
        "memory": 1.0,
        "threads": 1.0,
        "connections": 1.0,
        "files": 1.0,

        # -----------------------------------------
        # Aggregated trust
        # -----------------------------------------
        "dynamic_trust": 1.0,

        # -----------------------------------------
        # Static trust
        # binary / executable trust
        # -----------------------------------------
        "static_trust": 1.0,

        # -----------------------------------------
        # Final hybrid trust
        # slide 24
        # -----------------------------------------
        "final_trust": 1.0,

        # -----------------------------------------
        # Runtime metadata
        # -----------------------------------------
        "last_updated": None
    }


# ---------------------------------------------------
# INITIALIZE
# ---------------------------------------------------
def initialize_trust(pid):

    if pid not in trust_db:

        trust_db[pid] = (
            default_trust_state()
        )


# ---------------------------------------------------
# UPDATE DYNAMIC VECTOR
# ---------------------------------------------------
def update_dynamic_trust(

    pid,

    cpu=None,
    memory=None,
    threads=None,
    connections=None,
    files=None
):

    initialize_trust(pid)

    state = trust_db[pid]

    # -----------------------------------------
    # component updates
    # -----------------------------------------
    if cpu is not None:
        state["cpu"] = round(
            cpu,
            3
        )

    if memory is not None:
        state["memory"] = round(
            memory,
            3
        )

    if threads is not None:
        state["threads"] = round(
            threads,
            3
        )

    if connections is not None:
        state["connections"] = round(
            connections,
            3
        )

    if files is not None:
        state["files"] = round(
            files,
            3
        )

    # -----------------------------------------
    # Dynamic trust aggregation
    #
    # normalized behavioral mean
    #
    # fixes:
    # cpu/file/net limitation
    # -----------------------------------------
    dynamic_components = [

        state["cpu"],
        state["memory"],
        state["threads"],
        state["connections"],
        state["files"]
    ]

    state["dynamic_trust"] = round(

        sum(dynamic_components)

        /

        len(dynamic_components),

        3
    )


# ---------------------------------------------------
# STATIC TRUST
# ---------------------------------------------------
def update_static_trust(
    pid,
    static_score
):

    initialize_trust(pid)

    trust_db[pid][
        "static_trust"
    ] = round(

        max(
            0.0,
            min(
                1.0,
                static_score
            )
        ),

        3
    )


# ---------------------------------------------------
# FINAL TRUST
#
# PPT slide 24
#
# T(p,t)
# = αTs + (1-α)Td
# ---------------------------------------------------
def compute_final_trust(
    pid,
    alpha=0.2
):

    initialize_trust(pid)

    state = trust_db[pid]

    static_score = (
        state[
            "static_trust"
        ]
    )

    dynamic_score = (
        state[
            "dynamic_trust"
        ]
    )

    final_score = round(

        (

            alpha
            *
            static_score

            +

            (
                1
                -
                alpha
            )
            *
            dynamic_score
        ),

        3
    )

    state[
        "final_trust"
    ] = final_score

    return final_score


# ---------------------------------------------------
# GET TRUST
# ---------------------------------------------------
def get_trust(pid):

    initialize_trust(pid)

    return dict(
        trust_db[pid]
    )


# ---------------------------------------------------
# REMOVE DEAD PROCESS
# ---------------------------------------------------
def remove_trust(pid):

    if pid in trust_db:
        del trust_db[pid]


# ---------------------------------------------------
# CLEAR ALL
# ---------------------------------------------------
def reset_trust():

    global trust_db

    trust_db = {}