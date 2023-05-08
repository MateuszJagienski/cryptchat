package org.example;

import javax.crypto.*;
import java.security.*;

public class RsaAuth {
    public static byte[] signWithPrivateKey(byte[] input, PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println(input.length);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.update(input);
        return cipher.doFinal();
    }

    public static byte[] signWithPublicKey(byte[] input, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }
    
    public static byte[] verifyWithPublicKey(byte[] enc, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decCipher = Cipher.getInstance("RSA");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] dec = decCipher.doFinal(enc);
        return dec;
        //return BytesToStringConverter.bytesToString(dec); // TODO: 5/6/2023
    }

    public static byte[] verifyWithPrivateKey(byte[] enc, PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decCipher = Cipher.getInstance("RSA");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] dec = decCipher.doFinal(enc);
        return dec;
        //return BytesToStringConverter.bytesToString(dec); // TODO: 5/6/2023
    }
}