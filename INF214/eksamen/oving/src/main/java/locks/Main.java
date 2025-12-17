package locks;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Main {
	Lock lock = new ReentrantLock();
	private ReadWriteLock rwlock = new ReentrantReadWriteLock();
	int value = 0;

	//reetrantLock
	public void methodA() {
		lock.lock();
		try {
			value++;
		}finally {
			lock.unlock();
		}
	}

	//readwriteLock
	public void increment() {
		while (true){
			rwlock.writeLock().lock();
			try {
				System.out.println("incrementing value");
				value++;
			}
			finally {
				try {
					Thread.sleep(1000);
					rwlock.writeLock().unlock();
					Thread.sleep(1);
				} catch (InterruptedException e) {
					throw new RuntimeException(e);
				}

			}
		}

	}

	public void readValue(){
		while (true){
			rwlock.readLock().lock();
			try {
				System.out.println("reading value: " + value);
			} catch (Exception e) {
				throw new RuntimeException(e);
			} finally {
				rwlock.readLock().unlock();
			}
		}
	}


	public static void main(String[] args) {
		Main main = new Main();
		for (int i = 0; i < 3; i++) {
			new Thread(main::readValue).start();
		}
		new Thread(main::increment).start();
	}
}