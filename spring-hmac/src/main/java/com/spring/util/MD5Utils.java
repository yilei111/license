package com.spring.util;


import org.apache.commons.lang3.StringUtils;

import java.security.MessageDigest;
import java.util.*;

public class MD5Utils {

    public static final String MAC_ALGORITHM_DEFAULT = "md5";

    /**
     * 签名规则：参数名按ASCII码从小到大排序（字典序）、MD5加密、大写转换
     *
     * @param map
     * @return java.lang.String
     * @author yilei
     * @date 2021-01-30 16:54
     */
    public static String encodeSign(SortedMap<String, String> map) {
        Set<Map.Entry<String, String>> entries = map.entrySet();
        Iterator<Map.Entry<String, String>> iterator = entries.iterator();
        List<String> values = new ArrayList();
        while (iterator.hasNext()) {
            Map.Entry entry = iterator.next();
            String k = String.valueOf(entry.getKey());
            String v = String.valueOf(entry.getValue());
            if (StringUtils.isNotEmpty(v) && entry.getValue() != null) {
                values.add(k + "=" + v);
            }
        }
        String sign = StringUtils.join(values, "&");
        System.out.println("拼接后字符串：" + sign);
        return encodeByMD5(sign).toUpperCase();
    }

    /**
     * MD5加密
     *
     * @param data
     * @return java.lang.String
     * @author yilei
     * @date 2021-01-30 16:50
     */
    public static String encodeByMD5(String data) {
        if (StringUtils.isBlank(data)) {
            return null;
        }
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(MAC_ALGORITHM_DEFAULT);
            messageDigest.update(data.getBytes("utf-8"));
            return getFormattedText(messageDigest.digest());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    private static String getFormattedText(byte[] digest) {
        StringBuffer buffer = new StringBuffer();
        //把每一个byte，做一个与运算，0xff
        for (byte b : digest) {
            // 加盐
            int number = b & 0xff;
            String str = Integer.toHexString(number);
            if (str.length() == 1) {
                buffer.append("0");
            }
            buffer.append(str);
        }
        //标准的md5加密后的结果
        return buffer.toString();
    }


    public static void main(String[] args) {

        TreeMap<String, String> stringStringTreeMap = new TreeMap<>();
        stringStringTreeMap.put("a", "aaaaaa");
        stringStringTreeMap.put("daaaa", "202020202");
        stringStringTreeMap.put("ab", "2111111");
        stringStringTreeMap.put("beee", "100.00");
        System.out.println("参数 " + stringStringTreeMap);
        String s = MD5Utils.encodeSign(stringStringTreeMap);
        System.out.println(s);
    }
}
