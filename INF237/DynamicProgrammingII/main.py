import sys


def parse_speed_to_milli(value: str) -> int:
    if "." not in value:
        return int(value) * 1000
    whole, frac = value.split(".", 1)
    frac = (frac + "000")[:3]
    return int(whole) * 1000 + int(frac)


def better(a, b):
    if a[0] != b[0]:
        return a if a[0] > b[0] else b
    return a if a[1] >= b[1] else b


def solve() -> None:
    data = sys.stdin.read().strip().splitlines()
    if not data:
        return

    n = int(data[0].strip())
    rows = []
    name_to_id = {}

    for i in range(n):
        name, speed_str, boss = data[i + 1].split()
        name_to_id[name] = i
        rows.append((name, parse_speed_to_milli(speed_str), boss))

    speeds = [0] * n
    children = [[] for _ in range(n)]
    root = -1

    for i, (name, speed, boss) in enumerate(rows):
        speeds[i] = speed
        if boss == "CEO":
            root = i
        else:
            children[name_to_id[boss]].append(i)

    order = []
    stack = [root]
    while stack:
        u = stack.pop()
        order.append(u)
        for v in children[u]:
            stack.append(v)

    dp0 = [(0, 0) for _ in range(n)]  # u not matched with parent
    dp1 = [(0, 0) for _ in range(n)]  # u matched with parent

    for u in reversed(order):
        base_teams = 0
        base_sum = 0
        for v in children[u]:
            base_teams += dp0[v][0]
            base_sum += dp0[v][1]

        dp1[u] = (base_teams, base_sum)
        best = dp1[u]  # case: u not matched with any child

        for v in children[u]:
            cand_teams = (
                base_teams
                - dp0[v][0]
                + dp1[v][0]
                + 1
            )
            cand_sum = (
                base_sum
                - dp0[v][1]
                + dp1[v][1]
                + min(speeds[u], speeds[v])
            )
            best = better(best, (cand_teams, cand_sum))

        dp0[u] = best

    teams, total_milli = dp0[root]
    avg = 0.0 if teams == 0 else total_milli / (1000.0 * teams)
    sys.stdout.write(f"{teams} {avg:.8f}\n")


if __name__ == "__main__":
    solve()
