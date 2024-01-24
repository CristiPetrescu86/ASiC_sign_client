package ro.client_sign_app.clientapp;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class LoginPage extends Application {
    @Override
    public void start(Stage primaryStage) throws IOException {
        Parent root = FXMLLoader.load(getClass().getResource("login-view.fxml"));
        primaryStage.setTitle("Login Page");
        primaryStage.setScene(new Scene(root, 650, 350));
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}