package INF102.lab2.list;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class ArrayListTest extends ListTest {

  @Override
  public List<Integer> getList() {
    return new ArrayList<Integer>();
  }

  @Test
  public void testEfficientAccess() {
    initializeList(100000);
    ListTimer timer = new ListTimer(1000);
    assertFasterThan("HeadAccess", timer.timeHeadAccess(list), 20);
    assertFasterThan("TailAccess", timer.timeTailAccess(list), 20);
    assertFasterThan("RandomAccess", timer.timeRandomAccess(list), 20);
  }

  @Test
  public void testEfficientTailInsert() {
    initializeList(10000);
    ListTimer timer = new ListTimer(1000);
    assertFasterThan("TailInsertion", timer.timeTailInsertion(list), 20);
  }

}
