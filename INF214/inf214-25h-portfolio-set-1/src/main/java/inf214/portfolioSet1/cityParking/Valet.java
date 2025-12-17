package inf214.portfolioSet1.cityParking;

import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ThreadLocalRandom;

import inf214.portfolioSet1.ThreadUtils;
import inf214.portfolioSet1.cityParking.Request.RequestTypes;

public class Valet extends Thread {

	CityParking cps;
	ParkingLot parkingLot;
	ConcurrentMap<String, Integer> registrationChars;

	public Valet(String name, CityParking cps, ParkingLot parkingLot) {
		super(name);
		this.cps = cps;
		this.parkingLot = parkingLot;
	}

	public void run() {
		while (true) {
			Request order = cps.parkingQueue().takeRequest(); // take a order

			if (order != null) { // did we get one?
				if (order.type() == RequestTypes.PARK) {

					parkCar(order.car());
					// wait a little while before the next attempt (Union mandated break)
					ThreadUtils.delay(ThreadLocalRandom.current().nextInt(10) + 1);

				} else if (order.type() == RequestTypes.PICKUP) {

					pickupCar(order.regNr());
					// wait a little while before the next attempt (Union mandated break)
					ThreadUtils.delay(ThreadLocalRandom.current().nextInt(10) + 1);

				} else if (order.type() == RequestTypes.END_OF_DAY) {
					System.out.println(this.getName() + ": end of day");
					break;
				}

			} else {
				Thread.onSpinWait();
			}
		}
	}

	private void parkCar(Car car) {
		parkingLot.waitUntilReserved();

		Supervisor s = cps.grabSupervisor(this);
		Camera c = cps.grabCamera(this);

		parkingLot.parkCar(car);
		cps.updateDatabase(car.getRegNr());
		s.superviseParking(this, c, car);

		cps.releaseSupervisor(s, this);
		cps.releaseCamera(c, this);
	}

	private void pickupCar(String regNr) {
		parkingLot.waitUntilParked(regNr);

		Supervisor s = cps.grabSupervisor(this);
		Camera c = cps.grabCamera(this);

		Car car = parkingLot.pickupCar(regNr);
		s.supervisePickUp(this, c, car);

		cps.releaseCamera(c, this);
		cps.releaseSupervisor(s, this);

	}
}
