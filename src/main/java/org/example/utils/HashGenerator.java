package org.example.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HashGenerator {

    public HashGenerator() {

    }

    public static byte[] hashMessageSHA(String message, String algorithm) throws NoSuchAlgorithmException {
        byte[] output = message.getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance(algorithm);
        return sha.digest(output);
    }

    public static byte[] hashMessageSHA(String message, String algorithm, int length) throws NoSuchAlgorithmException {
        byte[] output = message.getBytes(StandardCharsets.UTF_8);
        MessageDigest sha = MessageDigest.getInstance(algorithm);
        return Arrays.copyOf(sha.digest(output), length);
    }

    public static byte[] hashMessageSHA(byte[] message, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance(algorithm);
        return sha.digest(message);
    }

    public static byte[] hashMessageSHA(byte[] message, String algorithm, int length) throws NoSuchAlgorithmException {
        MessageDigest sha = MessageDigest.getInstance(algorithm);
        return Arrays.copyOf(sha.digest(message), length);
    }
}
