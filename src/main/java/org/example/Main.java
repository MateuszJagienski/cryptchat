package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;

// Press Shift twice to open the Search Everywhere dialog and type `show whitespaces`,
// then press Enter. You can now see whitespace characters in your code.
public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, IOException {

        // User connect and all necessary keys are generated, RSA.public, RSA.private
        User user1 = new User("user1", KeysGenerator.generateRsaKeyPair(2048));
        // Another user connect
        User user2 = new User("user2", KeysGenerator.generateRsaKeyPair(2048));
        // User1 start try start conversation with user2
            // perform diffie hellman between user1 and user2, use RSA to authenticate
            // all necessary data for d-h is generated
            // user1 sends public dh-key to user2 signed with RSA
            // user2 verify received key with user1.RSA.public
            // user2 sends public dh-key to user1 signed with user2.RSA.private
            // user1 verify received key with user2.RSA.public
            // if everything went correct both sides creates shared secret key that is used to encrypt messages\
        user1.setKeyPairDh(KeysGenerator.generateDhKeyPair(2048));
        user2.setKeyPairDh(KeysGenerator.generateDhKeyPair(2048));
        DiffieHellman Dh1 = new DiffieHellman(user1.getKeyPairDh().getPrivate());
        DiffieHellman Dh2 = new DiffieHellman(user2.getKeyPairDh().getPrivate());
        user1.setSharedSecret(Dh1.generateSharedSecret(user2.getKeyPairDh().getPublic().getEncoded(), true));
        user2.setSharedSecret(Dh2.generateSharedSecret(user1.getKeyPairDh().getPublic().getEncoded(), true));
        if (Arrays.equals(user1.getSharedSecret(), user2.getSharedSecret())) {
            System.out.println("Shared secret are equals!");
        }
        // waiting any message
        Message user1Message = new Message(user1.getName(), "hejka tu lenka", new Timestamp(System.currentTimeMillis()));
        var sk = new SecretKeySpec(Arrays.copyOf(user1.getSharedSecret(), 16), "AES");
        user1Message.setEncryptedText(CryptoHandler.encrypt(user1Message.getText(), sk).getBytes());
        System.out.println(BytesToStringConverter.bytesToString(user1Message.getEncryptedText()));
        var dec = CryptoHandler.decrypt(BytesToStringConverter.bytesToString(user1Message.getEncryptedText()), sk);
        System.out.println(dec);
        // if user1 sends message
            // create hash from not encrypted message
            // encrypt message with AES
            // send message
            // sign hashed message with user1.RSA.private
            // sign hashed message with user2.RSA.public

            // user2 receive message and signed hashed message
            // user2 decrypt message with shared key
            // user2 creates hash from decrypted message
            // user2 verify hash first with user2.RSA.private then with user1.RSA.public
            // user2 compares received hashes if are equal message wasn't changed during sending

        // back to waiting for message
    }
}