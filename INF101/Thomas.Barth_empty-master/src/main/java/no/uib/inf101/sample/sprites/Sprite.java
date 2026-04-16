package no.uib.inf101.sample.sprites;

import no.uib.inf101.sample.GamePanel;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

public class Sprite implements ISprite{
    private int x;
    private int y;
    private int heigth;
    private int width;
    private int strength;
    private boolean mirrored;


    private final GamePanel gp;
    private BufferedImage currentImg;
    private BufferedImage drawingImg;
    private BufferedImage bisepForStat;

    /**
     * Constructs a Sprite object with a reference to the GamePanel and MouseHandler.
     * It initializes the sprite with default values and sets the initial image for drawing.
     *
     * @param gp     The GamePanel instance which the sprite is part of.
     */
    public Sprite(GamePanel gp){
        this.gp = gp;
        setDefaultValues();
        drawingImg = currentImg;
    }



    @Override
    public void drawSprite(Graphics2D g2) {
        if(mirrored){
            g2.drawImage(drawingImg,x+width,y,-width,heigth,null);
        }else {
            g2.drawImage(drawingImg,x,y,width,heigth,null);
        }

        drawStats(g2);
    }

    @Override
    public void setDefaultValues() {
        this.heigth = 400;
        this.width = 150;
        this.strength = 5;
        mirrored = false;
        try {
            currentImg = ImageIO.read(new File("res/sprites/spriteDefault.png"));
            bisepForStat = ImageIO.read(new File("res/Other/BisepForStats.png"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void setValues(int x, int y, int width, int height) {
       this.x = x;
       this.y = y;
       this.width = width;
       this.heigth = height;
    }

    @Override
    public int getWidth() {
        return width;
    }

    @Override
    public int getHeight() {
        return heigth;
    }

    @Override
    public int getStrength() {
        return strength;
    }

    @Override
    public int getX() {
        return x;
    }

    @Override
    public int getY() {
        return y;
    }

    @Override
    public void mirrorTurn(boolean turn) {
        mirrored = turn;
    }

    @Override
    public void updateStrength(int deltaStrength) {
        strength+= deltaStrength;
        if(strength > 10){
            strength = 10;
        }
        if (strength < 0){
            strength = 0;
        }

    }

    @Override
    public void stopDrawing() {
        drawingImg = null;
    }

    @Override
    public void startDrawing() {
        drawingImg = currentImg;
    }

    @Override
    public boolean isMirrored() {
        return mirrored;
    }

    @Override
    public void drawStats(Graphics2D g2) {
        int boxWidth = 200;
        int boxHeigth = 25;
        int interval = 200/10;//strength step
        int boxX = gp.getWidth() - boxWidth - 15;
        int boxY = 15;
        g2.setColor(Color.black);
        g2.drawRect(boxX,boxY,boxWidth,boxHeigth);
        g2.setColor(Color.red);
        g2.fillRect(boxX,boxY,interval*strength,boxHeigth);
        Color myColor = new Color(255,255,255,50);
        g2.setColor(myColor);
        g2.fillRect(boxX-50,boxY-10,50,45);
        g2.drawImage(bisepForStat,boxX-50,boxY-7,45,40,null);
    }

}
