# Lab 2 - List and Runtime
This lab has two sections.
 1. Implement list interface
 2. Determine the runtime of code snippets

All tasks within both sections must be completed to pass this lab.

## Section 1 - LinkedList VS ArrayList

ArrayList and LinkedList are two implementations of the List interface. 
Each have their own appealing features which we will explore in this task.


## Singly linked list
In this task we have given you a simplified version of the List interface. The two classes ``ArrayList`` and ``LinkedList`` implements this interface. Both classes already have a decent amount of code, but is missing a couple methods.

For **ArrayList** implement:
1. ``get(index)``
2. ``add(index, element)``

For **LinkedList** we will start by implementing a singly linked list.
You should implement:
1. ``getNode(index)``
2. ``add(index, element)``

✅ Run LinkedListTest.java and ArrayListTest.java to see if your implementation is correct. If all tests except 
``testEfficientTailAccess()`` and ``testEfficientTailInsert()``
pass then this section of the lab is passed.

## Efficiency
Main.java performs a set of operations using both ArrayList and LinkedList:
  * Insertion
    - Insert an element at a random index
    - Insert an element at index 0
    - Insert an element at index size()-1
  * Access
    - Access an element at a random index
    - Access an element at index 0
    - Access an element at index size()-1

Each operation is repeated ``n`` times. Each operation is timed and compared for the two different datastructures.

Why do ArrayList and LinkedList perform differently at these operations? **Give a Big-O analysis**. <br></br>
You do not need to submit anything for this task other than the implementation described above. However, this sort of reflection is fundamental for INF102 and you should always think about the runtime of you code.

### Expected output
```
----100 000 Random Insertions----
ArrayList      | time elapsed: 29401197 microseconds (29,401197 seconds)
LinkedList     | time elapsed: 87446   microseconds (0,087446 seconds)
LINKEDLIST BEST
LinkedList spent 0,3 % of the time ArrayList did.

----100 000 Head Insertions----
ArrayList      | time elapsed: 152155512 microseconds (152,155512 seconds)
LinkedList     | time elapsed: 4919    microseconds (0,004919 seconds)
LINKEDLIST BEST
LinkedList spent 0,0 % of the time ArrayList did.

----100 000 Tail Insertions----
ArrayList      | time elapsed: 7737    microseconds (0,007737 seconds)
LinkedList     | time elapsed: 82289935 microseconds (82,289935 seconds)
ARRAYLIST BEST
ArrayList spent 0,0 % of the time LinkedList did.

----100 000 Random Access----
ArrayList      | time elapsed: 5790    microseconds (0,005790 seconds)
LinkedList     | time elapsed: 43667244 microseconds (43,667244 seconds)
ARRAYLIST BEST
ArrayList spent 0,0 % of the time LinkedList did.

----100 000 Head Access----
ArrayList      | time elapsed: 2467    microseconds (0,002467 seconds)
LinkedList     | time elapsed: 1290    microseconds (0,001290 seconds)
LINKEDLIST BEST
LinkedList spent 52,3 % of the time ArrayList did.

----100 000 Tail Access----
ArrayList      | time elapsed: 2254    microseconds (0,002254 seconds)
LinkedList     | time elapsed: 86577698 microseconds (86,577698 seconds)
ARRAYLIST BEST
ArrayList spent 0,0 % of the time LinkedList did.
```

## Doubly linked list
If your implementation of the above Singly linked list is correct you see that Head insertion and head access is very fast compared to tail insertion and tail access.

A doubly linked list is a variant of linked list where the ``getNode(int index)`` method can choose to start from the beginning or from the end.

Your job is to modify the LinkedList implementation to become a doubly linked list.
You will need to do the following changes:

1. The Node class inside LinkedList needs to know both next and previous node.
2. The LinkedList class needs to know both head and tail
3. The ``getNode(int index) method`` needs to decide if it is best to start from head or tail.
4. The ``add(int index, T element)`` method needs to correctly update both previous and next of the Node objects.
Hint: the add method now has 3 special cases, adding to empty list, adding to index 0 and adding to index=size()

You should run Main and the tests to see if your implemetation is correct and faster. 

The two tests ``testEfficientTailAccess()`` and ``testEfficientTailInsert()`` should now pass.

## Section 2 - Runtime Analysis
In this section you will be analyzing a set of methods and determining their runtime. Select the runtime you think the method has and write your answer in `RuntimeAnswers.java`. If you think task A has runtime option **c)** then return the String `"c"` in `RuntimeAnswers::taskA`:
```java
public String taskA() {
    return "c";
}
```
All answers will be verifed on Codegrade. <br></br>
✅ **You must answer all questions correctly to pass this section.**

### Task A
```java
public double intrestLoan(double amount, int n) {
    for (int i = 0; i < n; i++) {
        amount = amount * 1.01;
    }
    return amount;
}
```
 a) O(1) <br></br>
 b) O(n<sup>2</sup>) <br></br>
 c) O(log(n)) <br></br>
 d) O(nlog(n)) <br></br>
 e) O(n<sup>2</sup>log(n)) <br></br>
 f) O(n<sup>3</sup>) <br></br>
 g) O(n)

### Task B
```java
public static int countOneBits(int n) {
    int bits = 0;
    while (n > 0) {
        if (n % 2 == 0) {
            bits++;
        }
        n = n / 2;
    }
    return bits;
}
```
 a) O(1) <br></br>
 b) O(n<sup>2</sup>) <br></br>
 c) O(log(n)) <br></br>
 d) O(nlog(n)) <br></br>
 e) O(n<sup>2</sup>log(n)) <br></br>
 f) O(n<sup>3</sup>) <br></br>
 g) O(n)

### Task C
```java
public static int countSteps(int n) {
    int pow = 2;
    int steps = 0;
    for (int i = 0; i < n; i++) {
        if (i == pow) {
            pow *= 2;
            for (int j = 0; j < n; j++) {
                steps++;
            }
        }
        else {
            steps++;
        }
    }
    return steps;
}
```
 a) O(1) <br></br>
 b) O(n<sup>2</sup>) <br></br>
 c) O(log(n)) <br></br>
 d) O(nlog(n)) <br></br>
 e) O(n<sup>2</sup>log(n)) <br></br>
 f) O(n<sup>3</sup>) <br></br>
 g) O(n)

### Task D
```java
public static String markRandomString(int n) {
    String ans = "";
    for (int i = 0; i < n; i++) {
        char c = (char) ('a' + 26*Math.random());
        ans += c;
    }
    return ans;
}
```
 a) O(1) <br></br>
 b) O(n<sup>2</sup>) <br></br>
 c) O(log(n)) <br></br>
 d) O(nlog(n)) <br></br>
 e) O(n<sup>2</sup>log(n)) <br></br>
 f) O(n<sup>3</sup>) <br></br>
 g) O(n)



✅ The lab is completed when the list implementations passes all tests and all the runtime answers are correct. To check this you must submit to Codegrade and see that you receive a score of **1/1**.
