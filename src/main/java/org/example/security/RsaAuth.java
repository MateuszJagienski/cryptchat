package org.example.security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import java.security.*;

public class RsaAuth {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static byte[] signWithPrivateKey(byte[] input, PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        System.out.println(input.length);
        cipher.update(input);
        return cipher.doFinal();
    }

    public static byte[] signWithPublicKey(byte[] input, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        System.out.println(input.length);
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input);
    }

    public static byte[] verifyWithPublicKey(byte[] enc, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, NoSuchProviderException {
        Cipher decCipher = Cipher.getInstance("RSA", "BC");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        return decCipher.doFinal(enc);
    }

    public static byte[] verifyWithPrivateKey(byte[] enc, PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        Cipher decCipher = Cipher.getInstance("RSA", "BC");
        decCipher.init(Cipher.DECRYPT_MODE, key);
        return decCipher.doFinal(enc);
    }
}