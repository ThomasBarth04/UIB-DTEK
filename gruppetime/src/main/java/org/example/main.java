package org.example;

import java.util.ArrayList;
import java.util.List;

public class main {
  public static void main(String[] args) throws InterruptedException {
    List<Character> characters = new ArrayList<>();
    characters.add(new Knight("Bjorn", 0, 0));
    characters.add(new Wizard("Lyra", 5, 2));
    characters.add(new Archer("Kael", 2, 4));

    for (int frame = 1; frame <= 5; frame++) {
      System.out.println("\nFrame " + frame);
      for (Character character : characters) {
        character.update();
        character.draw();
      }
      Thread.sleep(500);
    }
  }

  public static <E> E getFirst(E[] arr) {
    return arr[0];
  }
}
