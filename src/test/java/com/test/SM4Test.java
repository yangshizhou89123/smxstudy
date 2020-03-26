package com.test;

import com.smx.sm4.SM4Utils;

public class SM4Test {
    /**
     * 测试加密解密
     */
    public  void testEncryptDecrypt() {
        try {
            String message = "DSDSD";
            // 自定义的32位16进制密钥
            String key = "86C63180C2806ED1F47B859DE501215B";
            String cipher = SM4Utils.encryptEcb(key, message);
            System.out.println(cipher);//05a087dc798bb0b3e80553e6a2e73c4ccc7651035ea056e43bea9d125806bf41c45b4263109c8770c48c5da3c6f32df444f88698c5c9fdb5b0055b8d042e3ac9d4e3f7cc67525139b64952a3508a7619
            System.out.println(SM4Utils.verifyEcb(key, cipher, message));// true
            message = SM4Utils.decryptEcb(key, cipher);
            System.out.println(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
