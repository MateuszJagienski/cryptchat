package org.example.security;


import org.example.utils.BytesToStringConverter;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AesCipher {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int IV_SIZE = 128;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String TAG_DATA = "ASD";

    public static String encrypt(String plainText, SecretKey secretKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        byte[] data = plainText.getBytes(StandardCharsets.UTF_8);

        // initiliaze random IV
        byte[] IV = new byte[IV_SIZE];
        secureRandom.nextBytes(IV);

        // add tag data
        byte[] aadTagData = TAG_DATA.getBytes(StandardCharsets.UTF_8);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, IV);

        // initialize cipher
        System.out.println("secretKey: " + BytesToStringConverter.bytesToHex(secretKey.getEncoded()));
        Cipher encCipher = Cipher.getInstance("AES/GCM/NOPADDING");
        encCipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec, secureRandom);
        encCipher.updateAAD(aadTagData);
        byte[] enc = encCipher.doFinal(data);

        // concattanate tag and IV vector with encrypted data
        byte[] ivCTAndTag = new byte[IV.length + enc.length];
        System.arraycopy(IV, 0, ivCTAndTag, 0, IV.length);
        System.arraycopy(enc, 0, ivCTAndTag, IV.length, enc.length);

        // with UTF_8 lose tag data for some reason Base64
        return Base64.getEncoder().encodeToString(ivCTAndTag);
    }

    public static String decrypt(String enc, SecretKey secretKey) throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, IOException, NoSuchPaddingException {
        // data to decrypt

        byte[] decodedToDecrypt = Base64.getDecoder().decode(enc);

        // copy data from encrypted text to IV vector
        byte[] IV = new byte[IV_SIZE];
        System.arraycopy(decodedToDecrypt, 0, IV, 0, IV.length);

        byte[] aadTagData = TAG_DATA.getBytes(StandardCharsets.UTF_8);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, IV);

        // encrypted bytes without additional data
        byte[] encryptedBytes = new byte[decodedToDecrypt.length - IV.length];
        System.arraycopy(decodedToDecrypt, IV.length, encryptedBytes, 0, encryptedBytes.length);

        Cipher decCipher = Cipher.getInstance("AES/GCM/NOPADDING");
        decCipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec, secureRandom);
        decCipher.updateAAD(aadTagData);
        byte[] dec = decCipher.doFinal(encryptedBytes);
        return BytesToStringConverter.bytesToString(dec);
    }
}
