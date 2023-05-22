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
import com.vaadin.flow.router.*;
import org.example.models.Message;
import org.example.security.AesCipher;
import org.example.security.KeysGenerator;
import org.example.security.RsaAuth;
import org.example.utils.BytesToStringConverter;
import org.example.utils.HashGenerator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.UnicastProcessor;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;
import java.util.Random;

import static com.vaadin.flow.component.Tag.H3;

@Route("chatroom1")
@PreserveOnRefresh
public class ChatRoomView1 extends VerticalLayout  {

    private final UnicastProcessor<Message> publisher;
    private final Flux<Message> messages;
    private static final HashMap<String, PublicKey> publicRsaKeys = new HashMap<>();;
    private final HashMap<String, SecretKey> secretAesKeys = new HashMap<>();
    private KeyPair rsaKeyPair;
    private String username;
    private final Div chatBox;
    private TextField sendTo;

    public ChatRoomView1(UnicastProcessor<Message> publisher, Flux<Message> messages) {
        this.publisher = publisher;
        this.messages = messages;
        setSizeFull();
        setDefaultHorizontalComponentAlignment(Alignment.CENTER);
        // Initialize chat box
        chatBox = new Div();
        // Initialize input field
       // RouterLink link = new RouterLink("Home", MainView.class);
        // Add components to layout

        askUsername();
        HorizontalLayout horizontalLayout = new HorizontalLayout();
        horizontalLayout.add(chatBox);
        sendTo = new TextField("Send to user");


        horizontalLayout.add(sendTo);
        add(horizontalLayout);
    }

    private void receive() throws NoSuchAlgorithmException, InvalidKeyException {
        MessageList messageList = new MessageList();

        add(messageList, createInputLayout());
        expand(messageList);

        messages.subscribe(message -> {
            getUI().ifPresent(
                    ui -> ui.access(() -> {
                        if (message.getEncryptedAesKey() != null) {
                            try {
                                var aesKey = RsaAuth.verifyWithPrivateKey(message.getEncryptedAesKey(), rsaKeyPair.getPrivate());
                                System.out.println("aes key " + BytesToStringConverter.bytesToStringBase64(aesKey));
                                System.out.println("aes key len "   + aesKey.length);
                                if (aesKey.length <= 32)
                                    secretAesKeys.put(message.getAuthorName(), new SecretKeySpec(aesKey, 0, aesKey.length, "AES"));
                            } catch (Exception ignored) {}
                            return;
                        }
                        var decryptedMessage = decryptMessage(message);
                        String text = message.getAuthorName() + ": " + decryptedMessage;
                        var isVerified = verifyMessage(message.getSignature(), message.getAuthorName(), decryptedMessage);
                        if (isVerified)
                            text += " (verified)";
                        FlexLayout messageLayout = new FlexLayout();

                        TextArea textArea = new TextArea();
                        textArea.setValue(text);
                        textArea.setMaxLength(250);
                        messageLayout.add(textArea);

                        Span timestamp = new Span(String.valueOf(message.getTimestamp()));
                        messageLayout.add(timestamp);
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
            String encryptedMessage = null;
            byte[] signature;
            Message message = new Message(username, new Timestamp(System.currentTimeMillis()));
            try {
                encryptedMessage = encryptMessage(messageToEncrypt, sendTo.getValue());
                message.setEncryptedText(encryptedMessage);
            } catch (Exception ignored) {}
            try {
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
            System.out.println("signing message " + message);
            byte[] firstHash = HashGenerator.hashMessageSHA(message.getBytes(), "SHA-256");
            byte[] firstSign = RsaAuth.signWithPrivateKey(firstHash, rsaKeyPair.getPrivate());
            signature = RsaAuth.signWithPublicKey(firstSign, publicRsaKeys.get(sendTo.getValue()));
            System.out.println("signature " + BytesToStringConverter.bytesToStringBase64(signature));
//
//            byte[] hashedMessage = HashGenerator.hashMessageSHA(message, "SHA-256");
//            byte[] signature = RsaAuth.signWithPrivateKey(hashedMessage, keyPair.getPrivate());
//            byte[] signatureWithPublicKey = RsaAuth.signWithPublicKey(signature, keyPairRemote.getPublic());




        } catch (Exception e) {
            e.printStackTrace();
        }
        return signature;
    }

    private boolean verifyMessage(byte[] signature, String authorName, String receivedMessage) {
        try {
            System.out.println("verifying message " + receivedMessage);
            var hashFromMessage = HashGenerator.hashMessageSHA(receivedMessage.getBytes(), "SHA-256");
            var first = RsaAuth.verifyWithPrivateKey(signature, rsaKeyPair.getPrivate());
            var second = RsaAuth.verifyWithPublicKey(first, publicRsaKeys.get(authorName));
            System.out.println("second " + BytesToStringConverter.bytesToStringBase64(second));
            return Arrays.equals(second, hashFromMessage);
        } catch (Exception e) {
            e.printStackTrace();
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
        System.out.println("secret aes to exchange: " + secretAes);
        System.out.println("sendto : " + sendTo);
        System.out.println("public rsa " + publicRsaKeys.get(sendTo));
        var signedSecretAes = RsaAuth.signWithPublicKey(secretAes.getEncoded(), publicRsaKeys.get(sendTo));
        Message message = new Message(username, new Timestamp(System.currentTimeMillis()));
        message.setEncryptedAesKey(signedSecretAes);
        System.out.println("signed secret aes " + Arrays.toString(signedSecretAes));
        secretAesKeys.put(sendTo, secretAes);
        publisher.onNext(message);
    }


    private void askUsername() {
        HorizontalLayout layout = new HorizontalLayout();
        TextField usernameField = new TextField();
        Button startButton = new Button("Start chat");

        layout.add(usernameField, startButton);

        startButton.addClickListener(click -> {
            username = usernameField.getValue();
            if (username == null || username.isEmpty()) {
                var rnd = new Random();
                username = "Anon" + rnd.nextInt(100000);
            }
            remove(layout);
            var div = new Div();
            div.add(username);
            add(div);
            try {
                receive();
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException(e);
            }
            try {
                rsaKeyPair = KeysGenerator.generateRsaKeyPair(2048);
                publicRsaKeys.put(username, rsaKeyPair.getPublic());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        });
        add(layout);
    }




}



