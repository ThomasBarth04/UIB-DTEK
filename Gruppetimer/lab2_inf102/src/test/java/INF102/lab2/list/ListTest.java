package INF102.lab2.list;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Random;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public abstract class ListTest {
  List<Integer> list;

  @BeforeEach
  public void setup() {
    list = getList();
  };

  abstract List<Integer> getList();

  protected void initializeList(int size) {
    for (int i = 0; i < size; i++) {
      list.addLast(i);
    }
  }

  @Test
  public void addSingleElementTest() {
    Integer element = 42;
    list.addLast(element);
    assertEquals(element, list.get(0));
  }

  @Test
  public void add100ElementsTest() {
    for (Integer i = 0; i < 100; i++) {
      list.addLast(i);
      assertEquals(i, list.get(i));
    }
    for (int i = 0; i < 100; i++) {
      assertEquals(i, list.get(i));
    }
  }

  @Test
  public void sizeTest() {
    assertEquals(0, list.size());
    Integer nElements = 100;
    for (Integer i = 0; i < nElements; i++) {
      list.addLast(i);
      assertEquals((i + 1), list.size());
    }
    assertEquals(nElements, (Integer) list.size());
  }

  public void addNElements(List<Integer> list, int n) {
    for (Integer i = 0; i < n; i++) {
      list.addLast(i);
    }
  }

  @Test
  public void insertTest() {

    Integer nElements = 100;
    addNElements(list, nElements);
    int currentSize = list.size();

    Integer element = 42;
    Integer index = 50;
    list.add(index, element);
    assertEquals(element, list.get(index));

    Integer newSize = list.size();
    assertEquals(currentSize, newSize - 1);

    for (int i = 0; i <= 100; i++) {
      if (i < index) {
        assertEquals(i, list.get(i));
      }

      if (i > index) {
        assertEquals(i - 1, list.get(i));
      }

    }
  }

  @Test
  public void headInsert() {
    Integer nElements = 100;
    addNElements(list, nElements);

    Integer element = 42;
    Integer index = 0;
    list.add(index, element);
    assertEquals(element, list.get(index));

    for (int i = 0; i < 100; i++) {
      assertEquals(i, list.get(i + 1));
    }

  }

  @Test
  public void tailInsert() {
    Integer nElements = 100;
    addNElements(list, nElements);

    Integer element = 42;
    Integer index = list.size() - 1;
    list.add(index, 42);
    assertEquals(element, list.get(index));
  }

  @Test
  public void accessEmptyList() {
    Assertions.assertThrows(IndexOutOfBoundsException.class, () -> {
      list.get(0);
    });
  }

  @Test
  public void accessAboveBound() {
    Assertions.assertThrows(IndexOutOfBoundsException.class, () -> {
      Integer nElements = 100;
      addNElements(list, nElements);
      Integer index = nElements;
      list.get(index);
    });
  }

  @Test
  public void insertManyRandom() {
    Random rand = new Random();

    Integer nElements = ArrayList.DEFAULT_CAPACITY * 3;
    addNElements(list, nElements);

    for (Integer i = 0; i < nElements; i++) {
      Integer randomIndex = rand.nextInt(list.size());
      Integer randomNumber = rand.nextInt(1000);
      list.add(randomIndex, randomNumber);
      assertEquals(randomNumber, list.get(randomIndex));
    }

    assertEquals(nElements * 2, list.size());
  }

  protected void assertFasterThan(String method, long time, long limit) {
    assertTrue(time < limit,
        "Method " + method + " used " + time + "ms time when expected was less than " + limit + "ms");
  }
}
