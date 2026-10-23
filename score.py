PENALTY = {"high": 25, "medium": 8, "low": 0}
UNASSESSED_PENALTY = 8   # if the AI could not judge a port, treat it as medium


def compute_score(findings, results, mitigated_ports):
    penalty = 0
    for f in findings:
        if f["exposure"] != "NETWORK-REACHABLE":
            continue
        if f["port"] in mitigated_ports:
            continue
        assessment = results.get(f["id"])
        penalty += PENALTY[assessment["risk"]] if assessment else UNASSESSED_PENALTY
    return max(0, 100 - penalty)


def grade(score):
    if score >= 90:
        return "Good"
    if score >= 70:
        return "Fair"
    return "At risk"