package inf112;

import com.badlogic.gdx.backends.lwjgl3.Lwjgl3ApplicationConfiguration;
import com.badlogic.gdx.utils.Os;
import com.badlogic.gdx.utils.SharedLibraryLoader;
import inf112.core.Config;
import inf112.game.Game;
import org.lwjgl.system.Configuration;
import com.badlogic.gdx.backends.lwjgl3.Lwjgl3Application;

public class Main {
    public static void main(String[] args) {
        // Needed to run app on macOS
        if (SharedLibraryLoader.os == Os.MacOsX) {
            Configuration.GLFW_LIBRARY_NAME.set("glfw_async");
        }

        Lwjgl3ApplicationConfiguration cfg = new Lwjgl3ApplicationConfiguration();
        cfg.setTitle(Config.WINDOW_TITLE);
        cfg.setWindowedMode(Config.SCREEN_WIDTH, Config.SCREEN_HEIGHT);
        cfg.setForegroundFPS(Config.FPS);

        new Lwjgl3Application(new Game(Config.VIEW_WIDTH, Config.VIEW_HEIGHT), cfg);
    }
}
