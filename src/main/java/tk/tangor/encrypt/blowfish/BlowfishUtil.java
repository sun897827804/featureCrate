import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

public class BlowfishUtil {

    private static final String ALGORITHM = "Blowfish";
    private static final String TRANSFORMATION_ECB = "Blowfish/ECB/PKCS5Padding";
    private static final String TRANSFORMATION_CBC = "Blowfish/CBC/PKCS5Padding";
    private static final String TRANSFORMATION_CFB = "Blowfish/CFB/PKCS5Padding";
    private static final String TRANSFORMATION_OFB = "Blowfish/OFB/PKCS5Padding";
    /**
     *  CBC、CFB 和 OFB 模式，IV（初始化向量）长度必须为8个字节长度
     */
    private static final Integer IV_LENGTH = 8;
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
    public static String encrypt(String data, String key, String transformation,String initIV) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {

        Key secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        Cipher cipher = Cipher.getInstance(transformation);

        if (transformation.contains("CBC") || transformation.contains("CFB") || transformation.contains("OFB")) {
            // 对于 CBC、CFB 和 OFB 模式，需要使用 IV（初始化向量）
            IvParameterSpec iv = new IvParameterSpec(initIV.getBytes(StandardCharsets.UTF_8));
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }

        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String encryptedData, String key, String transformation,String initIV) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {

        Key secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), ALGORITHM);
        Cipher cipher = Cipher.getInstance(transformation);

        if (transformation.contains("CBC") || transformation.contains("CFB") || transformation.contains("OFB")) {
            IvParameterSpec iv = new IvParameterSpec(initIV.getBytes(StandardCharsets.UTF_8));
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
        }

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        try {
            String originalData = "Hello, Blowfish!";
            String secretKey = "ThisIsASecretKey";
            String initIV=getIV();
            // 使用ECB模式进行加密和解密
            String encryptedDataECB = encrypt(originalData, secretKey, TRANSFORMATION_ECB,initIV);
            System.out.println("Encrypted Data (ECB): " + encryptedDataECB);
            String decryptedDataECB = decrypt(encryptedDataECB, secretKey, TRANSFORMATION_ECB,initIV);
            System.out.println("Decrypted Data (ECB): " + decryptedDataECB);

            //使用CBC模式进行加密和解密
            String encryptedDataCBC = encrypt(originalData, secretKey, TRANSFORMATION_CBC,initIV);
            System.out.println("Encrypted Data (CBC): " + encryptedDataCBC);
            String decryptedDataCBC = decrypt(encryptedDataCBC, secretKey, TRANSFORMATION_CBC,initIV);
            System.out.println("Decrypted Data (CBC): " + decryptedDataCBC);

            //使用CFB模式进行加密和解密
            String encryptedDataCFB = encrypt(originalData, secretKey, TRANSFORMATION_CFB,initIV);
            System.out.println("Encrypted Data (CFB): " + encryptedDataCFB);
            String decryptedDataCFB = decrypt(encryptedDataCFB, secretKey, TRANSFORMATION_CFB,initIV);
            System.out.println("Decrypted Data (CFB): " + decryptedDataCFB);

            //使用OFB模式进行加密和解密
            String encryptedDataOFB = encrypt(originalData, secretKey, TRANSFORMATION_OFB,initIV);
            System.out.println("Encrypted Data (OFB): " + encryptedDataOFB);
            String decryptedDataOFB = decrypt(encryptedDataOFB, secretKey, TRANSFORMATION_OFB,initIV);
            System.out.println("Decrypted Data (OFB): " + decryptedDataOFB);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
