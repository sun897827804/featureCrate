package tk.tangor.encrypt.aes;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.util.StrUtil;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;

public class AesEncryptUtil {

    /**
     * 加密模式: ECB，算法/模式/补码方式 （不使用IV初始向量）
     */
    private static final String AES_ECB = "AES/ECB/PKCS5Padding";

    /**
     * 加密模式: CBC，算法/模式/补码方式
     */
    private static final String AES_CBC = "AES/CBC/PKCS5Padding";

    /**
     * 加密模式: CFB，算法/模式/补码方式
     */
    private static final String AES_CFB = "AES/CFB/PKCS5Padding";

    /**
     * AES 中的 IV 长度必须为16字节
     */
    private static final Integer IV_LENGTH = 16;


    /***
     * <h2>初始化向量（IV），它是一个随机生成的字节数组，用于增加加密和解密的安全性</h2>
     */
    public static String getIV() {
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < IV_LENGTH; i++) {
            int number = random.nextInt(str.length());
            sb.append(str.charAt(number));
        }
        return sb.toString();
    }


    /**
     * 加密模式 ECB
     */
    public static String encryptECB(String text, String key) {
        if (StrUtil.isBlank(text) || StrUtil.isBlank(key)) {
            return null;
        }
        try {
            // 创建AES加密器
            Cipher cipher = Cipher.getInstance(AES_ECB);
            //获取一个 AES 密钥规范
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            // 加密字节数组
            byte[] encryptedBytes = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
            // 将密文转换为 Base64 编码字符串
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * <h2>解密 - 模式 ECB</h2>
     *
     * @param text 需要解密的文本内容
     * @param key  解密的密钥 key
     */
    public static String decryptECB(String text, String key) {
        if (StrUtil.isBlank(text) || StrUtil.isBlank(key)) {
            return null;
        }
        // 将密文转换为16字节的字节数组
        byte[] textBytes = Base64.getDecoder().decode(text);
        try {
            // 创建AES加密器
            Cipher cipher = Cipher.getInstance(AES_ECB);

            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            // 解密字节数组
            byte[] decryptedBytes = cipher.doFinal(textBytes);
            // 将明文转换为字符串
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 加密 - 自定义加密模式
     *
     * @param text 需要加密的文本内容
     * @param key  加密的密钥 key
     * @param iv   初始化向量
     * @param mode 加密模式
     */
    public static String encrypt(String text, String key, String iv, String mode) {
        if (StrUtil.isBlank(text) || StrUtil.isBlank(key) || StrUtil.isBlank(iv)) {
            return null;
        }

        try {
            // 创建AES加密器
            Cipher cipher = Cipher.getInstance(mode);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8)));
            // 加密字节数组
            byte[] encryptedBytes = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
            // 将密文转换为 Base64 编码字符串
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 解密 - 自定义加密模式
     *
     * @param text 需要解密的文本内容
     * @param key  解密的密钥 key
     * @param iv   初始化向量
     * @param mode 加密模式
     */
    public static String decrypt(String text, String key, String iv, String mode) {
        if (StrUtil.isBlank(text) || StrUtil.isBlank(key) || StrUtil.isBlank(iv)) {
            return null;
        }
        // 将密文转换为16字节的字节数组
        byte[] textBytes = Base64.getDecoder().decode(text);
        try {
            // 创建AES加密器
            Cipher cipher = Cipher.getInstance(mode);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8)));
            // 解密字节数组
            byte[] decryptedBytes = cipher.doFinal(textBytes);
            // 将明文转换为字符串
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    public static void main(String[] args) {

        String text = FileUtil.readUtf8String(new File("src/main/resources/1000.txt"));

        String key16 = "1234567890123456"; // 16字节密钥
        String key24 = "123456789012345678901234"; // 24字节密钥
        String key32 = "12345678901234567890123456789012"; // 32字节密钥


        String encryptTextEBC = encryptECB(text, key32);
        System.out.println("EBC 加密后内容：" + encryptTextEBC);
        System.out.println("EBC 解密后内容：" + decryptECB(encryptTextEBC, key32));
        System.out.println("\n\n");

        String iv = getIV();

        String encryptTextCBC = encrypt(text, key32, iv, AES_CBC);
        System.out.println("CBC 加密IV：" + iv);
        System.out.println("CBC 加密后内容：" + encryptTextCBC);
        System.out.println("CBC 解密后内容：" + decrypt(encryptTextCBC, key32, iv, AES_CBC));
        System.out.println("\n\n");

        String encryptTextCFB = encrypt(text, key32, iv, AES_CFB);
        System.out.println("CFB 加密IV：" + iv);
        System.out.println("CFB 加密后内容：" + encryptTextCFB);
        System.out.println("CFB 解密后内容：" + decrypt(encryptTextCFB, key32, iv, AES_CFB));

    }

}
