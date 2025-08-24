package INF102.lab2.list;

import java.util.Random;
import java.util.function.Consumer;

public class ListTimer {

	static Random rand = new Random();
	int N_OPERATIONS = 10000;

	public ListTimer(int repeats) {
		N_OPERATIONS = repeats;
	}
	
	/**
	 * Computes time to insert <code>n</code> elements in <code>list</code> at random indices
	 * 
	 * @param list of integers
	 * @return the time taken
	 */	
	public long timeRandomInsertions(List<Integer> list) {
		return timeListMethod(list, l -> randomInsertion(l));
	}

	private void randomInsertion(List<Integer> list) {
		for (int i = 0; i < N_OPERATIONS; i++) {
			int randomIndex = rand.nextInt(list.size() - 1);
			list.add(randomIndex, 42);
		}
	}


	/**
	 * Computes time to insert <code>n</code> elements in <code>list</code>. Each new element at the
	 * end of the list.
	 * 
	 * @param list of integers
	 * @return the time taken
	 */
	public long timeTailInsertion(List<Integer> list) {
		return timeListMethod(list, l -> tailInsertion(l));
	}

	private void tailInsertion(List<Integer> list) {
		for (int i = 0; i < N_OPERATIONS; i++) {
			list.addLast(42);
		}
	}

	/**
	 * Computes time to insert <code>n</code> elements in <code>list</code>. Each new element at the
	 * start of the list.
	 * 
	 * @param list of integers
	 * @return the time taken
	 */
	public long timeHeadInsertion(List<Integer> list) {
		return timeListMethod(list, l -> headInsertion(l));
	}
		
	private void headInsertion(List<Integer> list) {
		for (int i = 0; i < N_OPERATIONS; i++) {
			list.add(0, 42);
		}
	}
	
	/**
	 * Time <code>method</code> with <code>list</code> as input
	 * @param list
	 * @param method
	 * @return milliseconds spent on operation
	 */
	private static long timeListMethod(List<Integer> list, Consumer<List<Integer>> method) {
		long startTime = System.nanoTime();
		method.accept(list);
		long endTime = System.nanoTime();
		long timeElapsed = (endTime - startTime) / 1000000;
		return timeElapsed;
	}
	
	/**
	 * Get <code>n</code> elements from <code>list</code> at random indices
	 * 
	 * @param list of integers
	 */
	public long timeRandomAccess(List<Integer> list) {
		return timeListMethod(list, l -> randomAccess(l));
	}
	
	private void randomAccess(List<Integer> list) {
		int listLength = list.size();
		for (int i = 0; i < N_OPERATIONS; i++) {
			int randomIndex = rand.nextInt(listLength - 1);
			list.get(randomIndex);
		}
	}

	/**
	 * Get <code>n</code> elements from <code>list</code> at index 0
	 * 
	 * @param list of integers
	 */
	public long timeHeadAccess(List<Integer> list) {
		return timeListMethod(list, l -> headAccess(l));
	}
	
	private void headAccess(List<Integer> list) {
		int m = Math.min(list.size(), 10);
		for (int i = 0; i < N_OPERATIONS; i++) {
			list.get(i%m);
		}
	}

	/**
	 * Get <code>n</code> elements from <code>list</code> at index 0
	 * 
	 * @param list of integers
	 */
	public long timeTailAccess(List<Integer> list) {
		return timeListMethod(list, l -> tailAccess(l));
	}
	
	private void tailAccess(List<Integer> list) {
		int m = Math.min(list.size(), 10);
		int listLength = list.size();
		for (int i = 0; i < N_OPERATIONS; i++) {
			list.get(listLength - 1 -i%m);
		}
	}
}
