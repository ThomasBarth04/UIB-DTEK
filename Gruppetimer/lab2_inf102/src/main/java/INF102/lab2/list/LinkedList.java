package INF102.lab2.list;

public class LinkedList<T> implements List<T> {

  private int size;

  /**
   * If list is empty, head == null
   * else head is the first element of the list.
   */
  private Node<T> head;
  private Node<T> tail;

  @Override
  public int size() {
    return size;
  }

  @Override
  public boolean isEmpty() {
    return size == 0;
  }

  @Override
  public T get(int index) {
    if (index >= size())
      throw new IndexOutOfBoundsException(index);
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
    if (index < 0 || index >= size) {
      throw new IndexOutOfBoundsException();
    }

    if (index > size / 2) {
      return getFromTail(index);
    } else {
      return getFromHead(index);
    }
  }

  private Node<T> getFromTail(int index) {
    Node<T> current = tail;
    for (int i = size - 1; i > index; i--) {
      current = current.prev;
    }
    return current;
  }

  private Node<T> getFromHead(int index) {
    Node<T> current = head;
    for (int i = 0; i < index; i++) {
      current = current.next;
    }
    return current;
  }

  @Override
  public void add(int index, T element) {
    if (index < 0 || index > size) {
      throw new IndexOutOfBoundsException();
    }
    Node<T> newNode = new Node<T>(element);

    if (size == 0) {
      // case 1
      head = newNode;
      tail = newNode;

    } else if (index == 0) {
      // case 2
      newNode.next = head;
      head.prev = newNode;
      head = newNode;

    } else if (index == size) {
      // case 3
      newNode.prev = tail;
      tail.next = newNode;
      tail = newNode;

    } else {
      // case 4
      Node<T> current = getNode(index);

      current.prev.next = newNode;
      newNode.prev = current.prev;

      newNode.next = current;
      current.prev = newNode;

    }

    size++;
  }

  @Override
  public String toString() {
    StringBuilder str = new StringBuilder(size * 3 + 2);
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

  private class Node<E> {
    E data;
    Node<E> next;
    Node<E> prev;

    public Node(E data) {
      this.data = data;
    }
  }

  public static void main(String[] args) {
    LinkedList<Integer> l = new LinkedList<>();
    System.out.println("adding 4");
    for (int i = 0; i < 10; i++) {
      l.add(i, i);
    }
    l.add(7, 99);
    System.out.println(l);
  }
}
