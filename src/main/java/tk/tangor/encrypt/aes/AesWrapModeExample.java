package tk.tangor.encrypt.aes;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AesWrapModeExample {

    public static void main(String[] args) {
        try {

            /**
             // 使用密钥生成器生成原始密钥
             KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
             // 128位密钥
             keyGenerator.init(128);
             SecretKey keyToWrap = keyGenerator.generateKey();
             */
            String originalKey = "123456789012345678";
            SecretKeySpec originalSecret = new SecretKeySpec(originalKey.getBytes(StandardCharsets.UTF_8), "AES");

            /**
             * KeyGenerator.getInstance("AES")
             * 返回指定算法的 KeyGenerator 对象
             */
            // 生成另一个密钥，用于包装和解析原始密钥
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            /**
             * 指定所需密钥的大小
             */
            keyGen.init(128);
            /**
             * 生成加密的密钥
             */
            SecretKey encryptionKey = keyGen.generateKey();

            // 使用 WRAP_MODE 加密密钥
            byte[] wrappedKey = wrapKey(originalSecret, encryptionKey);

            // 使用 WRAP_MODE 解密密钥
            SecretKey unwrappedKey = unwrapKey(wrappedKey, encryptionKey);

            System.out.println("Original Key: " + Base64.getEncoder().encodeToString(originalSecret.getEncoded()));
            System.out.println("wrap Key：" + Base64.getEncoder().encodeToString(wrappedKey));
            System.out.println("Unwrapped Key: " + Base64.getEncoder().encodeToString(unwrappedKey.getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] wrapKey(SecretKey originalKey, SecretKey encryptionKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.WRAP_MODE, encryptionKey);
        return cipher.wrap(originalKey);
    }

    public static SecretKey unwrapKey(byte[] wrappedKey, SecretKey encryptionKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.UNWRAP_MODE, encryptionKey);
        return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }
}