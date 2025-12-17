package condition;

import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Main {

	Lock lock = new ReentrantLock();
	Condition stackNotEmpty = lock.newCondition();
	Condition stackNotFull = lock.newCondition();
	int[] stack = new int[10];
	int stackSize = 0;

	private void addToStack(int value){
		while (true){
			lock.lock();
			try{
				if(stackSize == 10){
					stackNotFull.await();
				}
				stackSize++;
				System.out.println(Thread.currentThread().getName() + ":" + stackSize);
				stack[stackSize-1] = value;
				stackNotEmpty.signal();
			}catch (InterruptedException e){
				e.printStackTrace();
			}
			finally {
				lock.unlock();
			}
		}
	}

	private int removeFromStack(){
		int value = 0;
		while (true){
			try {
				if(stackSize == 0){
					System.out.println("waiting for stackNotEmpty");
					stackNotEmpty.await();
				}
				lock.lock();
				value = stack[stackSize-1];
				System.out.println(Thread.currentThread().getName() + " removed: " + value);
				stackSize--;
				stackNotFull.signal();
			}catch (InterruptedException e){
				e.printStackTrace();
			}finally {
				lock.unlock();
			}
		}
	}

	public static void main(String[] args) {
		Main main = new Main();
		new Thread(() -> {
			try {
				main.addToStack(1);
			}catch (Exception e){
				e.printStackTrace();
			}
		}).start();
		new Thread(() -> {
			try {
				main.removeFromStack();
			}catch (Exception e){
				e.printStackTrace();
			}
		}).start();
	}

}


