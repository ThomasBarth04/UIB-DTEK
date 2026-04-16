package org.example;

public abstract class Character {
  protected final String name;
  protected int x;
  protected int y;

  protected Character(String name, int x, int y) {
    this.name = name;
    this.x = x;
    this.y = y;
  }

  public void moveTo(int x, int y) {
    this.x = x;
    this.y = y;
  }

  public abstract void update();

  public abstract void draw();
}
