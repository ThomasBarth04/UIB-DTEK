from math import comb

ret = 0
stack = 0
n = int(input())
completed = [0]

for i, x in enumerate(input()):
    if x == '(':
        completed.append(0) 
        stack += 1
    else:
        if stack > 0:
            ret += 1
            ret += comb(completed.pop(),2)
            stack -= 1
            completed[-1] += 1
        else:
            ret += comb(completed[0],2)
            completed[0] = 0
ret += comb(completed[0],2)
print(ret)
