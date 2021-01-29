package com.spring.util;

import org.apache.commons.lang3.StringUtils;
import sun.misc.BASE64Encoder;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.TreeMap;

/**
 * 签名、校验接口
 *
 * @author yilei
 * @className SignatrueTest
 * @date 2021/1/30 17:33
 **/
public class SignatrueUtils {

    public static final String MAC_ALGORITHM_DEFAULT = "HmacSHA1";

    /**
     * 密钥生成器（手动保存）
     *
     * @param
     * @return java.lang.String
     * @author yilei
     * @date 2021-01-30 15:12
     */
    public static String generateSecret() throws NoSuchAlgorithmException {
        //String secretKey = UUID.randomUUID().toString().replaceAll("-", "");
        // 得到一个 指定算法密钥的密钥生成器
        KeyGenerator gen = KeyGenerator.getInstance(MAC_ALGORITHM_DEFAULT);
        //生成一个密钥
        SecretKey secretKey = gen.generateKey();
        byte[] encoded = secretKey.getEncoded();
        String encBase64 = new BASE64Encoder().encode(encoded);
        return encBase64;
    }

    /**
     * 签名生成器
     *
     * @param data      明文消息
     * @param secretKey 密钥
     * @return java.lang.String
     * @author yilei
     * @date 2021-01-30 15:14
     */
    public static String getSignature(String data, String secretKey) {
        return hamcsha1(data.getBytes(), secretKey.getBytes());
    }

    /**
     * 签名验证
     *
     * @param secretKey 密钥
     * @param signatrue 签名
     * @param data      明文消息
     * @return boolean
     * @author yilei
     * @date 2021-01-30 15:18
     */
    public static boolean verifySignature(String secretKey, String signatrue, String data) {
        if (StringUtils.isBlank(secretKey)) {
            return false;
        }
        return StringUtils.equals(signatrue, hamcsha1(data.getBytes(), secretKey.getBytes()));
    }

    /**
     * 获取基于哈希的消息验证代码
     *
     * @param data 消息内容字节数组
     * @param key  签名密钥字节数组
     * @return java.lang.String
     * @author yilei
     * @date 2021-01-30 15:15
     */
    private static String hamcsha1(byte[] data, byte[] key) {
        try {
            SecretKeySpec signingKey = new SecretKeySpec(key, MAC_ALGORITHM_DEFAULT);
            Mac mac = Mac.getInstance(MAC_ALGORITHM_DEFAULT);
            mac.init(signingKey);
            return byte2hex(mac.doFinal(data));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 字节数组转16进制
     *
     * @param b 字节数组
     * @return java.lang.String
     * @author yilei
     * @date 2021-01-30 15:16
     */
    public static String byte2hex(byte[] b) {
        StringBuilder hs = new StringBuilder();
        String stmp;
        for (int n = 0; b != null && n < b.length; n++) {
            stmp = Integer.toHexString(b[n] & 0XFF);
            if (stmp.length() == 1) {
                hs.append('0');
            }
            hs.append(stmp);
        }
        return hs.toString().toUpperCase();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // 1、获取分配密钥
        String secretKey = generateSecret();
        System.out.println("密钥：" + secretKey);

        // 2、参数按指定规则生成初步签名(这里先进行MD5加密，双重加密更安全）
        TreeMap<String, String> stringStringTreeMap = new TreeMap<>();
        stringStringTreeMap.put("a", "aaaaaa");
        stringStringTreeMap.put("daaaa", "202020202");
        stringStringTreeMap.put("ab", "2111111");
        stringStringTreeMap.put("beee", "100.00");
        System.out.println("需要进行签名的参数 " + stringStringTreeMap);
        String message = MD5Utils.encodeSign(stringStringTreeMap);
        System.out.println("初步签名:" + message);

        //3、通过HMACSHA1，生成最终签名
        String signatrue = getSignature(message, secretKey);
        System.out.println("最终签名signatrue：" + signatrue);

        // 4、将消息和签名同时传送，接收方进行校验签名
        System.out.println("签名验证结果：" + verifySignature(secretKey, signatrue, message));

    }
}

