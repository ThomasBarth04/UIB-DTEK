package no.uib.inf102.wordle.controller.AI;

import no.uib.inf102.wordle.model.Dictionary;
import no.uib.inf102.wordle.model.word.WordleWord;
import no.uib.inf102.wordle.model.word.WordleWordList;

import java.util.ArrayList;
import java.util.Map;

public class MyStrategy implements IStrategy {

  private Dictionary dictionary;
  private WordleWordList guesses;
  private int guessCount = 0;
  private ArrayList<WordleWord> feedbacks = new ArrayList<>();

  // avg: 3.455, Seed:14212l, N_games: 200
  public MyStrategy(Dictionary dictionary) {
    this.dictionary = dictionary;
    System.out.println(dictionary.getAnswerWordsList().size());
    reset();
  }

  @Override
  public String makeGuess(WordleWord feedback) {
    if (feedback != null) {
      guesses.eliminateWords(feedback);
      feedbacks.add(feedback);
    }
    if (guessCount < 1) {
      guessCount++;
      Map<Character, Integer>[] letterFrequencies = guesses.calculateLetterFrequencies(guesses.possibleAnswers());
      return guesses.calculateFirstGuess(guesses.possibleAnswers(), letterFrequencies);
    }

    return guesses.bestGuessBasedOnEntropy();
  }

  @Override
  public void reset() {
    // TODO: Implement me :)
    feedbacks.clear();
    guessCount = 0;
    guesses = new WordleWordList(dictionary);
  }

}
