import java.util.*;


public class Main {
    public static void main(String[] args) {
        byte[] keyBytes = new byte[16];
        byte[] ivBytes = new byte[16];
        byte[] dataBytes = new byte[13];

        new Random().nextBytes(keyBytes);
        new Random().nextBytes(ivBytes);
        new Random().nextBytes(dataBytes);


        AESEncryptor encryptor = new AESEncryptor(keyBytes, ivBytes.clone());
        AESDecryptor decryptor = new AESDecryptor(keyBytes, ivBytes.clone());

        for (int i = 0; i < 5; i++) {
            byte[] encrypted = encryptor.encrypt(dataBytes);
            byte[] decryptyed = decryptor.decrypt(encrypted.clone());
        }
    }
}