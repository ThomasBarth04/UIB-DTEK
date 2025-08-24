package INF102.lab2.list;

import org.junit.jupiter.api.Test;

public class LinkedListTest extends ListTest{

	@Override
	List<Integer> getList() {
		return new LinkedList<Integer>();
	}

	@Override //speeds up tests for singleLinkedList
	protected void initializeList(int size) {
		for (int i = 0; i < size; i++) {
			list.addFirst(i);
		}
	}
	@Test
	public void testEfficientHeadAccess() {
		initializeList(100000);
		ListTimer timer = new ListTimer(1000);
		assertFasterThan("HeadAccess", timer.timeHeadAccess(list),20);
	}

	@Test
	public void testEfficientTailAccess() {
		initializeList(100000);
		ListTimer timer = new ListTimer(1000);
		assertFasterThan("TailAccess", timer.timeTailAccess(list),20);
	}

	@Test
	public void testEfficientHeadInsert() {
		initializeList(100000);
		ListTimer timer = new ListTimer(1000);
		assertFasterThan("HeadInsertion", timer.timeHeadInsertion(list),20);
	}

	@Test
	public void testEfficientTailInsert() {
		initializeList(100000);
		ListTimer timer = new ListTimer(1000);
		assertFasterThan("TailInsertion", timer.timeTailInsertion(list),20);
	}
}
