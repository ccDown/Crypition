package com.seven.crypition;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author kuan
 * Created on 2018/8/3.
 * @description
 */
public class Cryption {

    /**
     * Des加密
     *
     * @param key  密钥
     * @param date 明文
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] desencryption(byte[] key, byte[] date) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(DES_CRYPTION);
        SecretKeySpec secretKeySpec = getByteKey(key);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encryptDate = cipher.doFinal(date);
        return encryptDate;
    }


    /**
     * Des解密
     *
     * @param key    密钥
     * @param enDate 密文
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] desdecryption(byte[] key, byte[] enDate) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(DES_CRYPTION);
        SecretKeySpec secretKeySpec = getByteKey(key);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decryptionDate = cipher.doFinal(enDate);
        return decryptionDate;
    }

    /**
     * 3Des加密
     *
     * @param key  密钥
     * @param date 明文
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] threeDesEncryption(byte[] key, byte[] date) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(DES_EDE_CRYPTION);
        SecretKeySpec secretKeySpec = getByteThreeKey(key);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encryptDate = cipher.doFinal(date);
        return encryptDate;
    }

    /**
     * 3Des解密
     *
     * @param key    密钥
     * @param enDate 密文
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] threeDesDecryption(byte[] key, byte[] enDate) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(DES_EDE_CRYPTION);
        SecretKeySpec secretKeySpec = getByteThreeKey(key);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decryptionDate = cipher.doFinal(enDate);
        return decryptionDate;
    }

    /**
     * 3Des密钥
     * 格式化密钥长度为24
     *
     * @param key
     * @return
     */
    private static SecretKeySpec getByteThreeKey(byte[] key) {
        byte[] en_key = new byte[24];
        byte[] byte_key = key;
        switch (key.length) {
            case 8:
                System.arraycopy(byte_key, 0, en_key, 0, 8);
                System.arraycopy(byte_key, 0, en_key, 8, 8);
                System.arraycopy(byte_key, 0, en_key, 16, 8);
                break;
            case 16:
                System.arraycopy(byte_key, 0, en_key, 0, 16);
                System.arraycopy(byte_key, 0, en_key, 16, 8);
                break;
            default:
                en_key = byte_key;
                break;
        }

        SecretKeySpec secretKeySpec = new SecretKeySpec(en_key, DES_EDE);
        return secretKeySpec;
    }

    /**
     * 格式化密钥长度为8
     * @param key
     * @return
     */
    public static SecretKeySpec getByteKey(byte[] key) {
        byte[] keyBytes = key;
        //创建一个字节数组对密钥进行格式化
        byte[] byteTemp = new byte[8];
        for (int i = 0; i < keyBytes.length && i < byteTemp.length; i++) {
            byteTemp[i] = keyBytes[i];
        }

        SecretKeySpec desKey = new SecretKeySpec(byteTemp, DES);
        return desKey;
    }

    /**
     * 数据格式化为8的倍数
     * @param dataStr
     * @return
     */
    public static String dataFill(String dataStr) {
        int len = dataStr.length();
        if (len%16 != 0) {
            dataStr += "80";
            len = dataStr.length();
        }
        while (len%16 != 0) {
            dataStr += "0";
            len ++;
        }
        return dataStr;
    }

    public static final String DES = "Des";
    public static final String DES_CRYPTION = "DES/ECB/NoPadding";
    public static final String DES_EDE = "DESede";
    public static final String DES_EDE_CRYPTION = "DESEDE/ECB/NoPadding";

    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
        String key = "bc061946";
        String date = "06735980";
        System.out.println("开始进行加密");
        byte[] enDate = desencryption(key.getBytes(), date.getBytes());
        System.out.println("加密结果====" + ConvertUtil.bytesToHexString(enDate));
        byte[] deDate = desdecryption(key.getBytes(), enDate);
        System.out.println("解密结果====" + new String(deDate));


        String threeKey = "11223344556677881122334455667788";
        String threeDate = dataFill("12345");
        System.out.println("开始进行3Des加密   数据==="+threeDate);
        String threeEnDate = ConvertUtil.bytesToHexString(threeDesEncryption(ConvertUtil.hexStringToByte(threeKey), ConvertUtil.hexStringToByte(threeDate)));
        System.out.println("3Des加密结果====" + threeEnDate);
        String threeDeDate = ConvertUtil.bytesToHexString(threeDesDecryption(ConvertUtil.hexStringToByte(threeKey), ConvertUtil.hexStringToByte(threeEnDate)));
        System.out.println("3Des解密结果====" + threeDeDate);
    }
}
