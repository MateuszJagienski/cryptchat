package org.example;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashGenerator {

    public HashGenerator() {

    }

    public static byte[] hashMessageSHA(String message, String algorithm) throws NoSuchAlgorithmException {
        byte[] output = message.getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance(algorithm);
        return sha.digest(output);
    }
}
