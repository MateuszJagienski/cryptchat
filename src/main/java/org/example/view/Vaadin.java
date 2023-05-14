package org.example.view;

import com.nimbusds.jose.shaded.asm.Accessor;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.Key;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.Input;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.page.Push;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.Route;
import org.example.models.Message;
import reactor.core.publisher.Flux;
import reactor.core.publisher.UnicastProcessor;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;

public class Vaadin extends VerticalLayout {
    private Div chatBox;
    private TextField inputField;
    private Button sendButton;

    public Vaadin(UnicastProcessor<Message> messageDistributor, Flux<Message> messages) throws InvalidAlgorithmParameterException, IllegalBlockSizeException, IOException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        // Initialize chat box
        chatBox = new Div();
        // Initialize input field
        inputField = new TextField();
        inputField.setPlaceholder("Type your message here");
        // Initialize send button
        var ui = UI.getCurrent();
        sendButton = new Button("Send");
        sendButton.addClickListener(event -> {
            String message = inputField.getValue();
            var mes = new Message(message, "user1", new Timestamp(System.currentTimeMillis()));
            if (!message.isEmpty()) {
                // Send message to server using WebSocket or HTTP
                ui.access(() -> {
                    try {
                        add(message + "\n");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            //    chatBox.add(message + "\n");
                messageDistributor.onNext(mes);
                inputField.clear();
            }
        });

        messages.subscribe(this::add);
        sendButton.addClickShortcut(Key.ENTER);

        // Add components to layout
        add(chatBox, inputField, sendButton);
    }

    private void add(Message message) {
        try {
            chatBox.add(message.getAuthorName() + ": " + message.getText() + "\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String getNiggers() {
        return "nigger";
    }
}
