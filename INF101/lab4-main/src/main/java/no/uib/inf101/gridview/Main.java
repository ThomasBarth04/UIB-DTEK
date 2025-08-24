package no.uib.inf101.gridview;

import no.uib.inf101.colorgrid.CellPosition;
import no.uib.inf101.colorgrid.ColorGrid;
import no.uib.inf101.colorgrid.CellColor;


public class Main {
  public static void main(String[] args) {
    // TODO: Implement this method
    ColorGrid grid = new ColorGrid(3,4);
    grid.set(new CellPosition(0,0),Color.red);
    grid.set(new CellPosition(0,3),Color.blue);
    grid.set(new CellPosition(2,0),Color.yellow);
    grid.set(new CellPosition(2,3),Color.green);
    GridView gridW = new GridView(grid);
    JFrame frame = new JFrame();
    frame.setContentPane(gridW);
    frame.setTitle("ColorGrid");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.pack();
    frame.setVisible(true);
  }
}
