package INF102.lab2.list;

import java.text.DecimalFormat;
import java.util.Random;
import java.util.function.Consumer;

public class Main {

	static DecimalFormat formatter = new DecimalFormat("#, ###");

	static final int N_OPERATIONS = 20000;

	public static void main(String[] args) {
		
		//create lists
		List<Integer> arrayList = new ArrayList<>();
		List<Integer> linkedList = new LinkedList<>();

		int initalSize = 1000;
		for (int i = 0; i < initalSize; i++) {
			arrayList.addLast(i);
			linkedList.addLast(i);
		}

		ListTimer timer = new ListTimer(N_OPERATIONS);
		
		// For each operation (insertion and access) time the 
		// process for both LinkedList and ArrayList
		long timeElapsedArray;
		long timeElapsedLinked;

		// Random Insertion
		// ArrayList
		System.out.printf("----%sRandom Insertions----%n", formatter.format(N_OPERATIONS));
		System.out.printf("----on lists of size %s----%n", formatter.format(arrayList.size()));
		timeElapsedArray = timer.timeRandomInsertions(arrayList);
		printResult(arrayList, timeElapsedArray);
		// Linked List
		timeElapsedLinked = timer.timeRandomInsertions(linkedList);
		printResult(linkedList, timeElapsedLinked);
		printPercentage(timeElapsedArray, timeElapsedLinked);

		// Head Insertion
		// ArrayList
		System.out.printf("%n----%sHead Insertions----%n", formatter.format(N_OPERATIONS));
		System.out.printf("----on lists of size %s----%n", formatter.format(arrayList.size()));
		timeElapsedArray = timer.timeHeadInsertion(arrayList);
		printResult(arrayList, timeElapsedArray);
		// Linked List
		timeElapsedLinked = timer.timeHeadInsertion(linkedList);
		printResult(linkedList, timeElapsedLinked);
		printPercentage(timeElapsedArray, timeElapsedLinked);

		// Tail Insertion
		// ArrayList
		System.out.printf("%n----%sTail Insertions----%n", formatter.format(N_OPERATIONS));
		System.out.printf("----on lists of size %s----%n", formatter.format(arrayList.size()));
		timeElapsedArray = timer.timeTailInsertion(arrayList);
		printResult(arrayList, timeElapsedArray);
		// Linked List
		timeElapsedLinked = timer.timeTailInsertion(linkedList);
		printResult(linkedList, timeElapsedLinked);
		printPercentage(timeElapsedArray, timeElapsedLinked);

		// Random Access
		// ArrayList
		System.out.printf("%n----%sRandom Access----%n", formatter.format(N_OPERATIONS));
		System.out.printf("----on lists of size %s----%n", formatter.format(arrayList.size()));
		timeElapsedArray = timer.timeRandomAccess(arrayList);
		printResult(arrayList, timeElapsedArray);
		// Linked List
		timeElapsedLinked = timer.timeRandomAccess(linkedList);
		printResult(linkedList, timeElapsedLinked);
		printPercentage(timeElapsedArray, timeElapsedLinked);

		// Head Access
		// ArrayList
		System.out.printf("%n----%sHead Access----%n", formatter.format(N_OPERATIONS));
		System.out.printf("----on lists of size %s----%n", formatter.format(arrayList.size()));
		timeElapsedArray = timer.timeHeadAccess(arrayList);
		printResult(arrayList, timeElapsedArray);
		// Linked List
		timeElapsedLinked = timer.timeHeadAccess(linkedList); 
		printResult(linkedList, timeElapsedLinked);
		printPercentage(timeElapsedArray, timeElapsedLinked);

		// Tail Access
		// ArrayList
		System.out.printf("%n----%sTail Access----%n", formatter.format(N_OPERATIONS));
		System.out.printf("----on lists of size %s----%n", formatter.format(arrayList.size()));
		timeElapsedArray = timer.timeTailAccess(arrayList);
		printResult(arrayList, timeElapsedArray);
		// Linked List
		timeElapsedLinked = timer.timeTailAccess(linkedList);
		printResult(linkedList, timeElapsedLinked);
		printPercentage(timeElapsedArray, timeElapsedLinked);
	}

	private static void printResult(List<Integer> list, long milliSeconds) {
		String listType = list.getClass().getSimpleName();
		double seconds = milliSeconds / 1000.0;
		System.out.printf("%-15s| time elapsed: %-7d milliseconds (%f seconds)%n", listType, milliSeconds, seconds);
	}

	private static void printPercentage(double timeArray, double timeLinked) {
		if (timeArray > timeLinked) {
			double percentage = (timeLinked / timeArray) * 100.0;
			System.out.println("LINKEDLIST BEST");
			System.out.printf("LinkedList spent %.1f %% of the time ArrayList did.%n", percentage);
		} else {
			double percentage = (timeArray / timeLinked) * 100.0;
			System.out.println("ARRAYLIST BEST");
			System.out.printf("ArrayList spent %.1f %% of the time LinkedList did.%n", percentage);
		}
	}	
}
