package org.example;

public class Knight extends Character {
  public Knight(String name, int x, int y) {
    super(name, x, y);
  }

  @Override
  public void update() {
    x += 1;
  }

  @Override
  public void draw() {
    System.out.println("Knight " + name + " at (" + x + ", " + y + ") with sword");
  }
}
