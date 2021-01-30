package com.spring.util;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA 非对称加密工具类
 *
 * @author yilei
 * @className RsaUtils
 * @date 2021/1/30 15:39
 **/
public class RsaUtils {

    /**
     * 算法名称
     */
    private static final String ALGORITHM = "RSA";

    /**
     * 密钥长度
     */
    private static final int KEY_SIZE = 2048;

    /**
     * 密钥对生成器
     *
     * @param
     * @return void
     * @author yilei
     * @date 2021-01-30 15:39
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, IOException {
        // 获取指定算法的密钥对生成器
        KeyPairGenerator gen = KeyPairGenerator.getInstance(ALGORITHM);
        // 初始化密钥对生成器（指定密钥长度, 使用默认的安全随机数源）
        gen.initialize(KEY_SIZE);
        // 随机生成一对密钥（包含公钥和私钥）
        KeyPair keyPair = gen.generateKeyPair();
        return keyPair;
    }

    /**
     * 将 公钥/私钥 编码后以 Base64 的格式保存到指定文件
     *
     * @param key     公钥/私钥
     * @param fileUrl 文件路径
     * @return void
     * @author yilei
     * @date 2021/1/30 16:19
     */
    public static void saveToFile(Key key, String fileUrl) throws IOException {
        // 获取密钥编码后的格式
        byte[] encBytes = key.getEncoded();
        // 转换为 Base64 文本
        String encBase64 = new BASE64Encoder().encode(encBytes);
        // 保存到文件
        IOUtils.writeFile(encBase64, new File(fileUrl));
    }

    /**
     * 根据公钥的 Base64 文本创建公钥对象
     *
     * @param
     * @return void
     * @author yilei
     * @date 2021/1/30 15:52
     */
    public static PublicKey getPublicKey(String pubKeyBase64) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // 把 公钥的Base64文本 转换为已编码的 公钥bytes
        byte[] encPubKey = new BASE64Decoder().decodeBuffer(pubKeyBase64);
        // 创建 已编码的公钥规格
        X509EncodedKeySpec encPubKeySpec = new X509EncodedKeySpec(encPubKey);
        // 获取指定算法的密钥工厂, 根据 已编码的公钥规格, 生成公钥对象
        return KeyFactory.getInstance(ALGORITHM).generatePublic(encPubKeySpec);
    }

    /**
     * 根据私钥的 Base64 文本创建私钥对象
     *
     * @param
     * @return void
     * @author yilei
     * @date 2021/1/30 15:52
     */
    public static PrivateKey getPrivateKey(String priKeyBase64) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // 把 私钥的Base64文本 转换为已编码的 私钥bytes
        byte[] encPriKey = new BASE64Decoder().decodeBuffer(priKeyBase64);
        // 创建 已编码的私钥规格
        PKCS8EncodedKeySpec encPriKeySpec = new PKCS8EncodedKeySpec(encPriKey);
        // 获取指定算法的密钥工厂, 根据 已编码的私钥规格, 生成私钥对象
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(encPriKeySpec);
    }

    /**
     * 公钥加密数据
     *
     * @param plainData 明文
     * @param pubKey    公钥
     * @return byte[]
     * @author yilei
     * @date 2021/1/30 16:22
     */
    public static byte[] encryptPublic(byte[] plainData, PublicKey pubKey) throws Exception {
        // 获取指定算法的密码器
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        // 初始化密码器（公钥加密模型）
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        // 加密数据, 返回加密后的密文
        return cipher.doFinal(plainData);
    }

    /**
     * 私钥解密数据
     *
     * @param cipherData 密文
     * @param priKey     私钥
     * @return byte[]
     * @author yilei
     * @date 2021/1/30 16:24
     */
    public static byte[] decryptPrivate(byte[] cipherData, PrivateKey priKey) throws Exception {
        // 获取指定算法的密码器
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        // 初始化密码器（私钥解密模型）
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        // 解密数据, 返回解密后的明文
        return cipher.doFinal(cipherData);
    }

    /**
     * 公钥解密数据
     *
     * @param cipherData 密文
     * @param pubKey     公钥
     * @return byte[]
     * @author yilei
     * @date 2021/1/30 16:24
     */
    public static byte[] decryptPublic(byte[] cipherData, PublicKey pubKey) throws Exception {
        // 获取指定算法的密码器
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        // 初始化密码器（私钥解密模型）
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        // 解密数据, 返回解密后的明文
        return cipher.doFinal(cipherData);
    }

    /**
     * 私钥加密数据
     *
     * @param plainData 明文
     * @param priKey    私钥
     * @return byte[]
     * @author yilei
     * @date 2021/1/30 16:22
     */
    public static byte[] encryptPrivate(byte[] plainData, PrivateKey priKey) throws Exception {
        // 获取指定算法的密码器
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        // 初始化密码器（私钥加密模型）
        cipher.init(Cipher.ENCRYPT_MODE, priKey);
        // 加密数据, 返回加密后的密文
        return cipher.doFinal(plainData);
    }

    public static void main(String[] args) throws Exception {
        // 密钥对生成器
        KeyPair keyPair = generateKeyPair();
        // 公钥
        PublicKey pubKey = keyPair.getPublic();
        // 私钥
        PrivateKey priKey = keyPair.getPrivate();

        System.out.println("=============公钥加密，私钥解密(适用与客户端-服务器端模式）=================");
        // 明文
        String data = "RSA 非对称加密===公钥加密，私钥解密";
        System.out.println("明文:" + data);
        // 客户端: 用公钥加明文, 返回加密后的数据
        byte[] cipherData = encryptPublic(data.getBytes(), pubKey);
        // 服务端: 用私钥解密数据, 返回原文
        byte[] plainData = decryptPrivate(cipherData, priKey);
        // 输出查看解密后的原文
        System.out.println("私钥解密后：" + new String(plainData));

        System.out.println("");
        System.out.println("=============私钥加密，公钥解密（适用于签名验签授权模式）=================");
        // 明文
        String data1 = "RSA 非对称加密=====私钥加密，公钥解密";
        System.out.println("明文:" + data1);

        // 授权服务端: 用私钥加密明文, 返回加密后的数据
        byte[] cipherData1 = encryptPrivate(data1.getBytes(), priKey);
        // 被授权的服务端: 用公钥解密数据, 返回原文
        byte[] plainData1 = decryptPublic(cipherData1, pubKey);
        // 输出查看解密后的原文
        System.out.println("公钥解密后：" + new String(plainData1));

    }
}
