n = int(input())

parent = [None] * (n+1)
parent = [None,None]

workload = [None,0]
for u in range(2,n+1):
    p, d = (int(i) for i in input().split())
    parent.append(p)
    workload.append(d)

depth = [None] * (n+1)
depth[1] = 0
def get_depth(u):
    if depth[u] is not None:
        return depth[u]
    d = 1 + get_depth(parent[u])
    depth[u] = d
    return d

m = int(input())
for _ in range(m):
    orig_u, orig_v = (int(i) for i in input().split())
    u = orig_u
    v = orig_v
    time_u = 0
    time_v = 0
    while get_depth(u) > get_depth(v):
        # time_u += workload[parent[u]]
        time_u += workload[u]
        u = parent[u]
    while get_depth(u) < get_depth(v):
        # time_v += workload[parent[v]]
        time_v += workload[v]
        v = parent[v]
    while u != v:
        time_u += workload[u]
        time_v += workload[v]
        u = parent[u]
        v = parent[v]

    if time_u < time_v:
        print(orig_u, time_u)
    elif time_v < time_u:
        print(orig_v, time_v)
    elif get_depth(u) < get_depth(v):
        print(orig_u, time_u)
    elif get_depth(u) > get_depth(v):
        print(orig_v, time_v)
    else:
        print('No one')
