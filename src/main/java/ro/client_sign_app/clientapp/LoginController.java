package ro.client_sign_app.clientapp;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

public class LoginController {

    @FXML
    private TextField usernameField;

    @FXML
    private PasswordField passwordField;

    @FXML
    private void loginButtonAction(ActionEvent event) {
        String username = usernameField.getText();
        String password = passwordField.getText();

        // Replace this with your actual authentication logic
        if (authenticate(username, password)) {
            System.out.println("Login successful");
        } else {
            System.out.println("Login failed");
        }
    }

    // Sample authentication method (replace with your actual authentication logic)
    private boolean authenticate(String username, String password) {
        // In a real application, you would check against a database or other authentication system
        return username.equals("user") && password.equals("pass");
    }
}