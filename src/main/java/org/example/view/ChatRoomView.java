package org.example.view;

import com.vaadin.flow.component.Component;
import com.vaadin.flow.component.Key;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.messages.MessageList;
import com.vaadin.flow.component.orderedlayout.FlexLayout;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.textfield.TextArea;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.router.PreserveOnRefresh;
import com.vaadin.flow.router.Route;
import org.example.models.Message;
import org.example.security.AesCipher;
import org.example.security.KeysGenerator;
import org.example.security.RsaAuth;
import org.example.utils.HashGenerator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.UnicastProcessor;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;

@Route("chatroom")
@PreserveOnRefresh
public class ChatRoomView extends VerticalLayout {

    private final UnicastProcessor<Message> publisher;
    private final Flux<Message> messages;
    private static final HashMap<String, PublicKey> publicRsaKeys = new HashMap<>();
    private final HashMap<String, SecretKey> secretAesKeys = new HashMap<>();
    private KeyPair rsaKeyPair;
    private String username;
    private final Div chatBox;
    private final TextField sendTo;

    public ChatRoomView(UnicastProcessor<Message> publisher, Flux<Message> messages) {
        this.publisher = publisher;
        this.messages = messages;
        setSizeFull();
        setDefaultHorizontalComponentAlignment(Alignment.CENTER);
        chatBox = new Div();
        sendTo = new TextField("Send to user");

        askUsername();
        HorizontalLayout horizontalLayout = new HorizontalLayout();
        horizontalLayout.add(chatBox, sendTo);
        add(horizontalLayout);
    }

    private void askUsername() {
        HorizontalLayout layout = new HorizontalLayout();
        TextField usernameField = new TextField("Username");
        Button startButton = new Button("Start chat");
        startButton.addThemeVariants(ButtonVariant.LUMO_CONTRAST);
        startButton.addClickShortcut(Key.ENTER);
        usernameField.setRequired(true);
        usernameField.addValidationStatusChangeListener(e ->  startButton.setEnabled(!publicRsaKeys.containsKey(usernameField.getValue())));
        layout.add(usernameField, startButton);
        add(layout);
        startButton.addClickListener(click -> {
            if (usernameField.isEmpty()) return;
            username = usernameField.getValue();
            remove(layout);
            var div = new Div();
            div.add(username);
            add(div);
            try {
                receiveMessage();
                rsaKeyPair = KeysGenerator.generateRsaKeyPair(2048);
                publicRsaKeys.put(username, rsaKeyPair.getPublic());
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private void receiveMessage() throws NoSuchAlgorithmException, InvalidKeyException {
        MessageList messageList = new MessageList();

        add(messageList, createInputLayout());
        expand(messageList);

        messages.subscribe(message -> {
            getUI().ifPresent(ui -> ui.access(() -> {
                if (message.getEncryptedAesKey() != null) {
                    try {
                        var aesKey = RsaAuth.verifyWithPrivateKey(message.getEncryptedAesKey(), rsaKeyPair.getPrivate());
                        if (aesKey.length <= 32)
                            secretAesKeys.put(message.getAuthorName(), new SecretKeySpec(aesKey, 0, aesKey.length, "AES"));
                    } catch (Exception ignored) {}
                    return;
                }
                var decryptedMessage = decryptMessage(message);
                String text = message.getAuthorName() + ": " + decryptedMessage;
                var isVerified = verifyMessage(message.getSignature(), message.getAuthorName(), decryptedMessage);
                if (isVerified) text += " (verified)";

                FlexLayout messageLayout = new FlexLayout();
                TextArea textArea = new TextArea();
                textArea.setValue(text);
                textArea.setMaxLength(500);
                textArea.setMaxWidth("100%");
                messageLayout.add(textArea);

                Span timestamp = new Span(String.valueOf(message.getTimestamp()));
                messageLayout.add(timestamp);
                messageLayout.setWidth("100%");
                messageLayout.setMaxWidth("100%");
                messageLayout.getStyle().set("border", "5px solid #9E9E9E");
                messageLayout.setJustifyContentMode(JustifyContentMode.END);
                messageLayout.setAlignItems(Alignment.CENTER);
                messageLayout.setFlexDirection(FlexLayout.FlexDirection.COLUMN);
                messageLayout.getFlexWrap();
                messageLayout.setAlignSelf(Alignment.END);
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
            String messageToEncrypt = messageField.getValue();
            String encryptedMessage;
            byte[] signature;
            Message message = new Message(username, new Timestamp(System.currentTimeMillis()));
            try {
                encryptedMessage = encryptMessage(messageToEncrypt, sendTo.getValue());
                message.setEncryptedText(encryptedMessage);
                signature = signMessage(messageToEncrypt);
                message.setSignature(signature);
            } catch (Exception ignored) {}
            publisher.onNext(message);
            messageField.clear();
            messageField.focus();
        });
        sendButton.addClickShortcut(Key.ENTER);
        messageField.focus();
        return layout;
    }

    private byte[] signMessage(String message) {
        byte[] signature = null;
        try {
            byte[] firstHash = HashGenerator.hashMessageSHA(message.getBytes(), "SHA-256");
            byte[] firstSign = RsaAuth.signWithPrivateKey(firstHash, rsaKeyPair.getPrivate());
            signature = RsaAuth.signWithPublicKey(firstSign, publicRsaKeys.get(sendTo.getValue()));
        } catch (Exception ignored) {}
        return signature;
    }

    private boolean verifyMessage(byte[] signature, String authorName, String receivedMessage) {
        try {
            var hashFromMessage = HashGenerator.hashMessageSHA(receivedMessage.getBytes(), "SHA-256");
            var first = RsaAuth.verifyWithPrivateKey(signature, rsaKeyPair.getPrivate());
            var second = RsaAuth.verifyWithPublicKey(first, publicRsaKeys.get(authorName));
            return Arrays.equals(second, hashFromMessage);
        } catch (Exception e) {
            return false;
        }
    }

    private String encryptMessage(String messageToEncrypt, String sendTo) throws NoSuchAlgorithmException {
        if (!secretAesKeys.containsKey(sendTo)) {
            try {
                exchangeKeys(sendTo);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        try {
            return AesCipher.encrypt(messageToEncrypt, secretAesKeys.get(sendTo));
        } catch (Exception e) {
            return "failed to encrypt";
        }

    }

    private String decryptMessage(Message message) {
        try {
            var name = Objects.equals(message.getAuthorName(), username) ? sendTo.getValue() : message.getAuthorName();
            return AesCipher.decrypt(message.getEncryptedText(), secretAesKeys.get(name));
        } catch (Exception e) {
            return message.getEncryptedText();
        }
    }

    private void exchangeKeys(String sendTo) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        // send private aes key encrypted with rsa
        if (publicRsaKeys.get(sendTo) == null) {
            return;
        }
        var secretAes = KeysGenerator.generateAesKey(256);
        var signedSecretAes = RsaAuth.signWithPublicKey(secretAes.getEncoded(), publicRsaKeys.get(sendTo));
        Message message = new Message(username, new Timestamp(System.currentTimeMillis()));
        message.setEncryptedAesKey(signedSecretAes);
        secretAesKeys.put(sendTo, secretAes);
        publisher.onNext(message);
    }
}