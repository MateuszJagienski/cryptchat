package org.example.view;

import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.Anchor;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.messages.MessageList;
import com.vaadin.flow.component.orderedlayout.FlexLayout;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.*;
import com.vaadin.flow.server.VaadinSession;
import jakarta.annotation.PostConstruct;
import org.example.models.Message;
import org.example.models.User;
import org.example.security.AesCipher;
import org.example.security.DiffieHellman;
import org.example.security.KeysGenerator;
import org.example.utils.HashGenerator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.UnicastProcessor;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

@Route("chatroom")
@PreserveOnRefresh
public class ChatRoomView extends VerticalLayout implements BeforeEnterObserver, HasUrlParameter<String>, BeforeLeaveObserver {

    private final UnicastProcessor<Message> publisher;
    private final Flux<Message> messages;
    private static final HashMap<Integer, User> users = new HashMap<>();;
    private String username;
    private final Div chatBox;
    private final TextField inputField;
    private String chatId;
    private static int loggedUsers = 0;
    private static int bob = -1;
    private static int alice = -1;
    private int me = -1;
    public ChatRoomView(UnicastProcessor<Message> publisher, Flux<Message> messages) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        boolean f = false;
        if (bob == -1) {
            bob = loggedUsers;
            me = loggedUsers;
            f= true;
        }
        if (alice == -1 && !f) {
            alice = loggedUsers;
            me = loggedUsers;
        }
        loggedUsers++;
        this.publisher = publisher;
        this.messages = messages;
        setSizeFull();
        setDefaultHorizontalComponentAlignment(Alignment.CENTER);
        // Initialize chat box
        chatBox = new Div();
        // Initialize input field
        inputField = new TextField();
        inputField.setPlaceholder("Type your message here");
       // RouterLink link = new RouterLink("Home", MainView.class);
        Anchor anchor = new Anchor("/", "Home");
        // Add components to layout

        add(chatBox, inputField);
        add(anchor);
        askUsername();
        System.out.println("constructor me: " + me);
        System.out.println("constructor bob: " + bob);
        System.out.println("constructor alice: " + alice);
        if (me == alice || me == bob) {
            generateKeys();
        }
        if (loggedUsers == 2) {
        }


        if (loggedUsers == 2) {
            System.out.println("Chcecking if keys are the same");
            System.out.println("bob: " + bob);
            System.out.println("alice: " + alice);
            System.out.println("me: " + me);
            System.out.println("users size: " + users.size());
            System.out.println("shared secrets are equal?: " +
                    Arrays.equals(users.get(bob).getSharedSecret(),
                    users.get(alice).getSharedSecret()));
            System.out.println(Arrays.toString(users.get(bob).getSharedSecret()));
//            var aesKey = HashGenerator.hashMessageSHA(users.get(bob).getSharedSecret(), "SHA-256", 16);
//            users.get(bob).setSecretAesKey(new SecretKeySpec(aesKey, "AES"));
//            users.get(alice).setSecretAesKey(new SecretKeySpec(aesKey, "AES"));
        }

    }

    private void askUsername() {
        HorizontalLayout layout = new HorizontalLayout();
        TextField usernameField = new TextField();
        Button startButton = new Button("Start chat");

        layout.add(usernameField, startButton);

        startButton.addClickListener(click -> {
            username = usernameField.getValue();
            remove(layout);
            try {
                showChat();
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        });

        add(layout);
    }

    private void showChat() throws NoSuchAlgorithmException, InvalidKeyException {
        MessageList messageList = new MessageList();

        add(messageList, createInputLayout());
        expand(messageList);

        messages.subscribe(message -> {
            getUI().ifPresent(
                    ui -> ui.access(() -> {
                        String decText = message.getText();
                        if (me == bob || me == alice) {
                            try {
                                decText = AesCipher.decrypt(message.getText(), users.get(me).getSecretAesKey());
                            } catch (InvalidAlgorithmParameterException | InvalidKeyException |
                                     IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException |
                                     NoSuchPaddingException | IOException e) {
                                throw new RuntimeException(e);
                            }
                        }
                        //chatBox.add(new Paragraph(message.getAuthorName() + ": " + decText + "\t\t\t " + message.getTimestamp()));
                        FlexLayout messageLayout = new FlexLayout();
                        messageLayout.getStyle().set("display", "flex");
                        messageLayout.getStyle().set("flex-direction", "column");
                        messageLayout.getStyle().set("align-items", "flex-end");

                        Span messageText = new Span(message.getAuthorName() + ": " + decText);
                        messageText.getStyle().set("flex-grow", "1");
                        messageLayout.add(messageText);

                        Span timestamp = new Span(String.valueOf(message.getTimestamp()));
                        timestamp.getStyle().set("align-self", "flex-end");
                        messageLayout.add(timestamp);

                        chatBox.add(messageLayout);
                    }));

        });
    }

    private Component createInputLayout() {
        HorizontalLayout layout = new HorizontalLayout();
        layout.setWidth("100%");

        TextField messageField = new TextField();
        Button sendButton = new Button("Send");
        sendButton.addThemeVariants(ButtonVariant.LUMO_PRIMARY);

        layout.add(messageField, sendButton);
        layout.expand(messageField);

        sendButton.addClickListener(click -> {
            String mess = messageField.getValue();
            if (me == bob || me == alice) {
                try {
                    mess = AesCipher.encrypt(mess, users.get(me).getSecretAesKey());
                } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException |
                         BadPaddingException | UnsupportedEncodingException | InvalidAlgorithmParameterException |
                         NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            publisher.onNext(new Message(username, mess, new Timestamp(System.currentTimeMillis())));
            messageField.clear();
            messageField.focus();
        });
        messageField.focus();
        return layout;
    }

    private void generateKeys() throws NoSuchAlgorithmException, InvalidKeyException {
        if (me == -1) return;

        System.out.println("me generate keys: " + me);
        User user = new User(username, KeysGenerator.generateRsaKeyPair(4096));
        var dhKeys = KeysGenerator.generateDhKeyPair(2048);
        user.setKeyPairDh(dhKeys);
        DiffieHellman dh = new DiffieHellman(user.getKeyPairDh().getPrivate());
        user.setDiffieHellman(dh);
        users.put(me, user);
    }

    private void performDiffieHellman() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        System.out.println("performing diffie hellman");
        System.out.println(UI.getCurrent().getSession());
        System.out.println("me" + me);
        System.out.println("bob" + bob);
        System.out.println("alice" + alice);
        if (bob == -1 || alice == -1 || me == -1) return;
        int remote = me == bob ? alice : bob;
        var user = users.get(me);
        var remoteUser = users.get(remote);
        user.setSharedSecret(user.getDiffieHellman()
                .generateSharedSecret(
                        remoteUser.getKeyPairDh()
                        .getPublic().getEncoded(), true));


    }

    @Override
    public void beforeEnter(BeforeEnterEvent event) {
        chatId = event.getRouteParameters().get("chat_id").orElse(null);
    }

    @Override
    public void beforeLeave(BeforeLeaveEvent beforeLeaveEvent) {
        loggedUsers--;
        System.out.println("before leave" + loggedUsers);
    }

    @Override
    public void setParameter(BeforeEvent beforeEvent, String s) {
        chatId = s;
    }


}



