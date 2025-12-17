package inf214.portfolioSet1.cityTrafficLights;

public class Intersection {
  private TrafficLight trafficLight;

  public Intersection(TrafficLight trafficLight) {
    this.trafficLight = trafficLight;
  }

  public synchronized TrafficLight getTrafficLight() {
    if (trafficLight == null) {
      return null;
    }
    TrafficLight tl = trafficLight;
    trafficLight = null;
    return tl;
  }

  public synchronized void setTrafficLight(TrafficLight tl) {
    this.trafficLight = tl;
  }

  public synchronized boolean isAvailable() {
    return trafficLight != null;
  }

  public synchronized void reset() {
    if (trafficLight != null) {
      trafficLight.reset();
    }
  }
}
