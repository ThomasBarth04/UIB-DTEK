n =int(input())

xs = [int(i) for i in input().split()]

avg = sum(xs) / len(xs)

ret = 0
for x in xs:
    if x > avg:
        ret += 1

print(ret)
