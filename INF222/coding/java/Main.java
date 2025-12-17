import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Main {

  Number t = 10;

  public static void main(String[] args) {
    List<? super Integer> balle = new ArrayList<>();
    Number awd = 10;
    balle.add(awd);
    for (Object a : balle) {
      Integer g = (Integer) a;
      System.out.println(g);
    }

  }

}
