package com.inoi;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class KeyUtils {

    private final static String KEY_ALGORITHM = "EC";
    private final static String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private KeyPair keyPair;

    public static void main(String[] args) {
        KeyUtils keyUtils = new KeyUtils();
        try {
            KeyPair keyPair = keyUtils.generate();
            System.out.println("Private key: " + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            System.out.println("Public key: " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            //phoneNumber.deviceId.publicKey
            String strToEncode = "+12345000005.e49d6d3c-4e4d-40f3-b00b-81b51625f82f-chatbot." + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            System.out.println(keyUtils.sign(strToEncode).toString());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public KeyUtils(){
    }

    public KeyPair generate() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public String getEncodedPublicKey() {
        byte[] encoded = keyPair.getPublic().getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    public String sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(keyPair.getPrivate(), new SecureRandom());
        byte[] messageData = message.getBytes(StandardCharsets.UTF_8);
        signature.update(messageData);
        byte[] digitalSignature = signature.sign();
        return Base64.getEncoder().encodeToString(digitalSignature);
    }
}