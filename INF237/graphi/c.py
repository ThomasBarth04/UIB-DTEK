from math import log2, ceil

def left(i): return 2*i
def right(i): return 2*i+1
def parent(i): return i // 2
def index(T, i): return len(T) // 2 + i
def lookup(tree, i): return tree[index(tree, i)]

def update(idx, value, tree, op):
    idx = index(tree, idx)
    tree[idx] = value
    while (idx := parent(idx)) > 0:
        tree[idx] = op([tree[left(idx)], tree[right(idx)]])

def query_helper(tree, l, r):
    if l == r: 
        yield tree[l] # [l, r]
        return
    yield tree[l] # [l, r>
    yield tree[r] # [l, r]
    while True:
        pl, pr = parent(l), parent(r)
        if pl == pr: return
        if l % 2 == 0:                 # if left goes right, collect
            yield tree[right(pl)]
        if r % 2 == 1:                 # if right goes left, collect
            yield tree[left(pr)]
        l,r = pl, pr

def query(tree, l, r, op):
    return op(query_helper(tree, index(tree, l) , index(tree, r)))

n = int(input())
xs = [int(i) for i in input().split()]

internals = 2**(ceil(log2(n)))
comments = [9] * internals + xs + [0] * (internals-n)
for i in range(1,1+internals):
    comments[i] = min(left(i),right(i))

deleted = [0] * internals * 2 #n*[0]

print(comments)
print(deleted)