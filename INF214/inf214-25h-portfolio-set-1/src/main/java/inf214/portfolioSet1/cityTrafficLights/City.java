package inf214.portfolioSet1.cityTrafficLights;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import inf214.portfolioSet1.ThreadUtils;

public class City {

  private final List<Intersection> city = new ArrayList<>();
  private int timeDelay;
  private int day = 0;

  private Lock lock = new ReentrantLock();
  private final Condition okForOrdinary = lock.newCondition();
  private final Condition okForSpecial = lock.newCondition();

  private int activeOrdinary = 0;
  private boolean specialRequested = false;
  private boolean specialActive = false;

  public City(int size, int useLimit, int timeDelay) {
    for (int i = 0; i < size; i++) {
      TrafficLight tl = new TrafficLight(useLimit);
      city.add(new Intersection(tl));
    }
    this.timeDelay = timeDelay;
  }

  /**
   * At the start of each day, we reset the trafficlights
   */
  public synchronized void startDay() {
    for (Intersection i : city) {
      i.reset();
    }
    day++;
  }

  public int getCitySize() {
    return city.size();
  }

  public boolean isAvailable(int trafficLight) {
    return city.get(trafficLight).isAvailable();
  }

  public TrafficLight getTrafficLight(int i) {
    ThreadUtils.delay(timeDelay); // DO NOT remove the delay, you will get 0 points
    TrafficLight tl = city.get(i).getTrafficLight();
    return tl;
  }

  public void setTrafficLight(int i, TrafficLight trafficLight) {
    ThreadUtils.delay(timeDelay); // DO NOT remove the delay, you will get 0 points
    city.get(i).setTrafficLight(trafficLight);
  }

  public void requestAccess() {
    lock.lock();
    try {
      while (specialActive || specialRequested) {
        okForOrdinary.awaitUninterruptibly();
      }
      activeOrdinary++;
    } finally {
      lock.unlock();
    }
  }

  public void releaseAccess() {
    lock.lock();
    try {
      activeOrdinary--;
      if (activeOrdinary == 0 && specialRequested) {
        okForSpecial.signal();
      }
    } finally {
      lock.unlock();
    }
  }

  public void requestSpecialAccess() {
    lock.lock();
    try {
      if (activeOrdinary == 0) {
        specialActive = true;
        specialRequested = false;
      } else {
        specialRequested = true;
      }
    } finally {
      lock.unlock();
    }
  }

  public void releaseSpecialAccess() {
    lock.lock();
    try {
      specialActive = false;
      okForOrdinary.signal();
    } finally {
      lock.unlock();
    }
  }

  public boolean isCityEmpty() {
    lock.lock();
    boolean empty;
    try {
      empty = activeOrdinary == 0;
    } finally {
      lock.unlock();
    }
    return empty;
  }

  public void logAccess(String s) {
    System.out.printf("[Day %2d] %s%n", day, s);
  }
}
