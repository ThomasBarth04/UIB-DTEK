package org.example;

public class Wizard extends Character {
  public Wizard(String name, int x, int y) {
    super(name, x, y);
  }

  @Override
  public void update() {
    y += 2;
  }

  @Override
  public void draw() {
    System.out.println("Wizard " + name + " at (" + x + ", " + y + ") casting spell");
  }
}
