package inf214.portfolioSet1.cityParking;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

public class ParkingLot {
  private final int numParkingSpots;
  private Semaphore semaphoreSpots;
  private final ConcurrentHashMap<String, CompletableFuture<Car>> parkingLotMap = new ConcurrentHashMap<>();

  public ParkingLot(int numParkingSpots) {
    this.numParkingSpots = numParkingSpots;
    this.semaphoreSpots = new Semaphore(this.numParkingSpots);
  }

  /**
   * Reserves a parking spot in the parkinglot. This function is only to make sure
   * that we do not put more cars in the parkinglot than there are spaces. It
   * returns true if there is space for more cars and we managed to reserve one,
   * false otherwise (and a valet will havethis. to wait for space to become
   * available).
   * 
   * @return true if a parking space was reserved, and false otherwise.
   */
  public boolean reserveParking() {
    return semaphoreSpots.tryAcquire();
  }

  public void waitUntilReserved() {
    try {
      semaphoreSpots.acquire();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  public void waitUntilParked(String regNr) {
    try {
      parkingLotMap.computeIfAbsent(regNr, k -> new CompletableFuture<>()).get();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /**
   * Attempts to park the car in the parking lot. Returns true if there was space
   * and the car is parked, false if the parking lot was full
   * 
   * @param car the car to park.
   * @return true/false wheter the car got parked.
   */
  synchronized public void parkCar(Car car) {
    try {
      parkingLotMap.computeIfAbsent(car.getRegNr(), k -> new CompletableFuture<>()).complete(car);
      car.park();
    } catch (Exception e) {
      e.printStackTrace();
    }

  }

  public boolean isParked(String regNr) {
    return parkingLotMap.containsKey(regNr);
  }

  /**
   * Attempts to pick up the car in the parking lot. Returns the car object if we
   * found the car and the car is picked up, null if car was missing from the
   * parking lot. This should also decrease the amount of cars currently in the
   * parkinglot.
   * 
   * @param regNr the registration number of the car we want to pickup.
   * @return a Car object
   */
  synchronized public Car pickupCar(String regNr) {
    try {
      Car car = parkingLotMap.remove(regNr).get();
      car.pickUp();
      semaphoreSpots.release();
      return car;

    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }
}
