n, d = (int(i) for i in input().split())

iguanas = []
for _ in range(n):
    # print('hello?', n)
    t_sprint,t_rest,v_sprint = (int(i) for i in input().split())
    iguanas.append((t_sprint,t_rest,v_sprint))

    time = 0
    remaining = d
    while t_sprint * v_sprint < remaining:
        remaining -= t_sprint * v_sprint
        time += t_sprint + t_rest
    time += remaining / v_sprint
    print(time)
