package INF101.lab2;
import INF101.lab2.pokemon.Pokemon;
import INF101.lab2.pokemon.IPokemon;


public class Main {

    public static IPokemon pokemon1;
    public static IPokemon pokemon2;
    public static void main(String[] args) {
        pokemon1 = new Pokemon("Thomas");
        pokemon2 = new Pokemon("Markus");

        // Have two pokemon fight until one is defeated
        System.out.println(pokemon1 + "\n" + pokemon2);
        while (pokemon1.isAlive() && pokemon2.isAlive()){
            pokemon1.attack(pokemon2);
            if(pokemon2.isAlive()){
                pokemon2.attack(pokemon1);
            }
        }
    }
}
