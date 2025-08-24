package INF102.lab2.list;

public class ArrayList<T> implements List<T> {

  public static final int DEFAULT_CAPACITY = 10;

  private int size;

  private T[] elements;

  public ArrayList() {
    elements = createGenericArray(DEFAULT_CAPACITY);
  }

  @SuppressWarnings("unchecked")
  private T[] createGenericArray(int capacity) {
    return (T[]) new Object[capacity];
  }

  @Override
  public T get(int index) {
    if (index >= size) {
      throw new IndexOutOfBoundsException();
    }
    return elements[index];
  }

  @Override
  public void add(int index, T element) {
    if (size == elements.length) {
      T[] newElements = createGenericArray(elements.length * 2);
      for (int i = 0; i < elements.length; i++) {
        newElements[i] = elements[i];
      }
      elements = newElements;
    }
    if (elements[index] == null) {
      elements[index] = element;
      size++;
      return;
    }

    T temp = elements[index];
    elements[index] = element;
    add(index + 1, temp);
  }

  @Override
  public int size() {
    return size;
  }

  @Override
  public boolean isEmpty() {
    return size == 0;
  }

  @Override
  public String toString() {
    StringBuilder str = new StringBuilder(size * 3 + 2);
    str.append("[");
    for (int i = 0; i < size; i++) {
      str.append((T) elements[i]);
      if (i != size - 1)
        str.append(", ");
    }
    str.append("]");
    return str.toString();
  }
}
