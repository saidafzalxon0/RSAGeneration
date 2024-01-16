package org.example;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

public class RSAExample {
    public static void main(String[] args) throws Exception {
        // Matn
        String originalMessage = "RSA encode decode qilish";

        // RSA key pair generatsiya qilish
        KeyPair keyPair = generateKeyPair();

        // Ochiq kalit (public key) olish
        PublicKey publicKey = keyPair.getPublic();

        // Matnni shifrlash
        String encryptedMessage = encrypt(originalMessage, keyPair.getPrivate());
        System.out.println("Encrypted Message: " + encryptedMessage);

        // Shifrlangan matnni dekod qilish
        String decryptedMessage = decrypt(encryptedMessage, keyPair.getPublic(), keyPair.getPrivate());
        System.out.println("Decrypted Message: " + decryptedMessage);
    }

    // RSA key pair generatsiya qilish
    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Key uzunligi
        return keyPairGenerator.generateKeyPair();


    }

    // Matnni RSA orqali shifrlash
    private static String encrypt(String plainText, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);

        signature.update(plainText.getBytes());
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes) + "|" + plainText;
    }

    // Shifrlangan matnni dekod qilish
    private static String decrypt(String encryptedText, PublicKey publicKey, PrivateKey privateKey) throws Exception {
        String[] parts = encryptedText.split("\\|");
        String signaturePart = parts[0];
        String plainText = parts[1];

        byte[] signatureBytes = Base64.getDecoder().decode(signaturePart);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);

        signature.update(plainText.getBytes());

        if (signature.verify(signatureBytes)) {
            return plainText;
        } else {
            return "Decoding failed!";
        }
    }
}
