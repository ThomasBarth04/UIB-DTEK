package org.example;

public class Archer extends Character {
  public Archer(String name, int x, int y) {
    super(name, x, y);
  }

  @Override
  public void update() {
    x += 2;
    y += 1;
  }

  @Override
  public void draw() {
    System.out.println("Archer " + name + " at (" + x + ", " + y + ") with bow");
  }
}
