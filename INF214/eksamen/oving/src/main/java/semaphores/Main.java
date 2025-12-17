package semaphores;

import java.util.concurrent.Semaphore;

public class Main {

	Semaphore readValue = new Semaphore(3);
	Semaphore increment = new Semaphore(1);
	Semaphore threadIncrement = new Semaphore(1);
	int value = 0;
	int threadCount = 0;

	private void increment() {
		try {
			threadIncrement.acquire();
			threadCount++;
		}catch (InterruptedException e) {
			e.printStackTrace();
		}
		finally {
			threadIncrement.release();
		}

		while (threadCount < 20){
			Thread.onSpinWait();
		}
		while (true){
			try {
				increment.acquire();
				value++;
			} catch (InterruptedException e) {
				throw new RuntimeException(e);
			}finally {
				increment.release();
			}
		}

	}

	private void readValue() {
		try {
			threadIncrement.acquire();
			threadCount++;

		}catch (InterruptedException e) {
			e.printStackTrace();
		}
		finally {
			threadIncrement.release();
		}

		while (threadCount < 20){
			Thread.onSpinWait();
		}
		while (true){
			try {
				readValue.acquire();
				System.out.println(Thread.currentThread().getName() + ": readValue: " + value);
			}catch (Exception e) {
				throw new RuntimeException(e);
			}finally {
				try {
					Thread.sleep(100);
					readValue.release();
				}catch (InterruptedException e) {
					throw new RuntimeException(e);
				}
			}
		}
	}

	public static void main(String[] args) {
		Main main = new Main();
		for (int i = 0; i < 10; i++) {
			new Thread(main::readValue).start();
		}
		for (int i = 0; i < 10; i++) {
			new Thread(main::increment).start();
		}
		try {
			Thread.sleep(100);
		}catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
		System.out.println("threadcout: " + main.threadCount);

	}
}
