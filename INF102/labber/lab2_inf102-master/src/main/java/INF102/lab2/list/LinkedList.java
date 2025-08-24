package INF102.lab2.list;

public class LinkedList<T> implements List<T> {

  private int n;

  /**
   * If list is empty, head == null
   * else head is the first element of the list.
   */
  private Node<T> head;

  @Override
  public int size() {
    return n;
  }

  @Override
  public boolean isEmpty() {
    return n == 0;
  }

  @Override
  public T get(int index) {
    return getNode(index).data;
  }

  /**
   * Returns the node at the specified position in this list.
   *
   * @param index index of the node to return
   * @return the node at the specified position in this list
   * @throws IndexOutOfBoundsException if the index is out of range
   *                                   ({@code index < 0 || index >= size()})
   */
  private Node<T> getNode(int index) {
    if (index < 0 || index >= n)
      throw new IndexOutOfBoundsException();
    Node<T> returnNode = head;
    for (int i = 0; i < index; i++)
      returnNode = returnNode.next;
    return returnNode;
  }

  @Override
  public void add(int index, T element) {
    if (index < 0 || index > n)
      throw new IndexOutOfBoundsException();
    Node<T> newNode = new Node<>(element);
    if (index == 0) {
      newNode.next = head;
      head = newNode;
    } else {
      Node<T> currentNode = head;
      for (int i = 0; i < index - 1; i++)
        currentNode = currentNode.next;
      newNode.next = currentNode.next;
      currentNode.next = newNode;
    }
    n++;
  }

  @SuppressWarnings("unchecked")
  @Override
  public String toString() {
    StringBuilder str = new StringBuilder(n * 3 + 2);
    str.append("[");
    Node<T> currentNode = head;
    while (currentNode.next != null) {
      str.append(currentNode.data);
      str.append(", ");
      currentNode = currentNode.next;
    }
    str.append((T) currentNode.data);
    str.append("]");
    return str.toString();
  }

  @SuppressWarnings("hiding")
  private class Node<T> {
    T data;
    Node<T> next;

    public Node(T data) {
      this.data = data;
    }
  }

}
