package org.example;

import org.example.models.Message;
import org.example.models.User;
import org.example.security.AesCipher;
import org.example.security.DiffieHellman;
import org.example.security.KeysGenerator;
import org.example.security.RsaAuth;
import org.example.utils.BytesToStringConverter;
import org.example.utils.HashGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.sql.Timestamp;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

// Press Shift twice to open the Search Everywhere dialog and type `show whitespaces`,
// then press Enter. You can now see whitespace characters in your code.
public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException, IOException, SignatureException, NoSuchProviderException {

        // User connect and all necessary keys are generated, RSA.public, RSA.private
        User user1 = new User("user1", KeysGenerator.generateRsaKeyPair(2048));
        // Another user connec
        User user2 = new User("user2", KeysGenerator.generateRsaKeyPair(2048));
        // User1 start try start conversation with user2
            // perform diffie hellman between user1 and user2, use RSA to authenticate
            // all necessary data for d-h is generated
            // user1 sends public dh-key to user2
            // user2 received key
            // user2 sends public dh-key to user1
            // user1 received key
            // if everything went correct both sides creates shared secret key that is used to encrypt messages\
        user1.setKeyPairDh(KeysGenerator.generateDhKeyPair(2048));
        user2.setKeyPairDh(KeysGenerator.generateDhKeyPair(2048));

        DiffieHellman Dh1 = new DiffieHellman(user1.getKeyPairDh().getPrivate());
        DiffieHellman Dh2 = new DiffieHellman(user2.getKeyPairDh().getPrivate());

        user1.setSharedSecret(Dh1.generateSharedSecret(user2.getKeyPairDh().getPublic().getEncoded(), true));
        user2.setSharedSecret(Dh2.generateSharedSecret(user1.getKeyPairDh().getPublic().getEncoded(), true));

        // shared secret is used to generate private key for AES

        if (Arrays.equals(user1.getSharedSecret(), user2.getSharedSecret())) {
            System.out.println("Shared secret are equals!");
            var key = HashGenerator.hashMessageSHA(user1.getSharedSecret(), "SHA-256", 16);
            SecretKey sessionKey = new SecretKeySpec(key, "AES");
            user1.setSecretAesKey(sessionKey);
            user2.setSecretAesKey(sessionKey);
            System.out.println(user1.getSecretAesKey().getAlgorithm());
            System.out.println(user1.getSecretAesKey().getEncoded().length);
        }


        // waiting for message
        Message user1Message = new Message(user1.getName(), "hejka tu lenka", new Timestamp(System.currentTimeMillis()));
        System.out.println(user1.getSharedSecret().length);
        System.out.println(Arrays.copyOf(user1.getSharedSecret(), 16).length);
        System.out.println(user1.getSecretAesKey());

        user1Message.setEncryptedText(AesCipher.encrypt(user1Message.getText(), user1.getSecretAesKey()));
        System.out.println("enc mess" + user1Message.getEncryptedText());


        // if user1 sends message
        // create hash from not encrypted message
        // encrypt message with AES
        // send message
        // sign hashed message with user1.RSA.private
        // sign hashed message with user2.RSA.public
        var hashedMessage = HashGenerator.hashMessageSHA(user1Message.getText(), "SHA-1");
        var adsd = RsaAuth.signWithPublicKey(user1Message.getText().getBytes(), user2.getKeyPairRsa().getPublic());
        System.out.println("asdasdasda" + Arrays.toString(adsd));
        var dsds = RsaAuth.verifyWithPrivateKey(adsd, user2.getKeyPairRsa().getPrivate());
        System.out.println("dsdsdsdsds" + BytesToStringConverter.bytesToString(dsds));
        byte[] signedHashMessage = RsaAuth.signWithPrivateKey(hashedMessage, user1.getKeyPairRsa().getPrivate());
        user1Message.setSignature(signedHashMessage);

        // user2 receive message and signed hashed message
        // user2 decrypt message with shared key
        var dec = AesCipher.decrypt(user1Message.getEncryptedText(), user2.getSecretAesKey());
        // user2 creates hash from decrypted message
        var hashedMessage1 = HashGenerator.hashMessageSHA(dec, "SHA-1", 128);
        // user2 verify hash first with user2.RSA.private then with user1.RSA.public
        byte[] verifiedHash = RsaAuth.verifyWithPublicKey(signedHashMessage, user1.getKeyPairRsa().getPublic());
        // user2 compares received hashes if are equal message wasn't changed during sending
        if (Arrays.equals(hashedMessage1, verifiedHash)) {
            System.out.println("Hashes are equal!");
        }
        System.out.println(BytesToStringConverter.bytesToString(verifiedHash));
        System.out.println(BytesToStringConverter.bytesToHex(hashedMessage1));
        System.out.println("dec " + dec);
        // back to waiting for message
    }
}