import sys


class Node:
    def __init__(self, node_id):
        self.id = node_id
        self.neighbors = []


def valid_color(v, c, node_colors, nodes):
    for n in nodes[v].neighbors:
        if node_colors[n] == c:
            return False
    return True


def solve(a, k, node_colors, nodes, available_count):
    if a == len(nodes):
        return True

    v = -1
    bestC = k + 1

    for i in range(len(nodes)):
        if node_colors[i] != -1:
            continue
        if available_count[i] < bestC:
            v = i
            bestC = available_count[i]

    nReduced = []

    for c in range(1, k + 1):
        if not valid_color(v, c, node_colors, nodes):
            continue

        nReduced.clear()
        possible = True

        for n in nodes[v].neighbors:
            if node_colors[n] != -1:
                continue
            if valid_color(n, c, node_colors, nodes):
                available_count[n] -= 1
                nReduced.append(n)

                if available_count[n] == 0:
                    possible = False
                    break

        if not possible:
            for x in nReduced:
                available_count[x] += 1
            continue

        node_colors[v] = c

        if solve(a + 1, k, node_colors, nodes, available_count):
            return True

        node_colors[v] = -1

        for x in nReduced:
            available_count[x] += 1

    return False


def main():
    n = int(sys.stdin.readline().strip())

    nodes = [Node(i) for i in range(n)]

    for i in range(n):
        line = sys.stdin.readline().strip()
        if line:
            nodes[i].neighbors = list(map(int, line.split()))

    startK = 1
    for node in nodes:
        startK = max(startK, len(node.neighbors))

    for k in range(1, n + 1):
        color = [-1] * n
        available_count = [k] * n

        if solve(0, k, color, nodes, available_count):
            print(k)
            break


if __name__ == "__main__":
    main()
