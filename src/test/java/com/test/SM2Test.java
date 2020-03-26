package com.test;


import com.smx.sm2x.Signature;
import com.smx.sm2x.TransportEntity;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;
import com.smx.sm2x.SM2;
import com.smx.sm2x.SM2KeyPair;

import java.math.BigInteger;
import java.util.Arrays;

public class SM2Test {

    private static final String puA = "C:\\Users\\98383\\Desktop\\temp\\publickey.pem";
    private static final String prA = "C:\\Users\\98383\\Desktop\\temp\\privatekey.pem";

    @Before
    public void testExport(){
        SM2 sm02 = new SM2();
        SM2KeyPair sm2KeyPair = sm02.generateKeyPair();
        sm02.exportPublicKey(sm2KeyPair.getPublicKey(),puA);
        sm02.exportPrivateKey(sm2KeyPair.getPrivateKey(),prA);
    }

    /**
     * 测试加密解密
     */
    @Test
    public void testEncryptDecrypt(){
        System.out.println("-----------------公钥加密与解密-----------------");
        ECPoint publicKey = SM2.importPublicKey(puA);
        BigInteger privateKey = SM2.importPrivateKey(prA);
        byte[] data = SM2.encrypt("测试加密xxx3333", publicKey);
        System.out.print("密文:"+ Arrays.toString(data));
        //CommonUtils.printHexString(data);
        System.out.println("解密后明文:" + SM2.decrypt(data, privateKey));
    }

    /**
     * 测试验签和签名
     */
    @Test
    public void testSign(){
        ECPoint publicKey = SM2.importPublicKey(puA);
        BigInteger privateKey = SM2.importPrivateKey(prA);

        System.out.println("-----------------签名与验签-----------------");
        String IDA = "Heartbeats";
        String M = "要签名的信息";
        Signature signature = SM2.sign(M, IDA, new SM2KeyPair(publicKey, privateKey));
        System.out.println("用户标识:" + IDA);
        System.out.println("签名信息:" + M);
        System.out.println("数字签名:" + signature);
        System.out.println("验证签名:" + SM2.verify(M, signature, IDA, publicKey));

    }

    /**
     * 测试协商会话密钥
     */
    @Test
    public void testExchange(){

        System.out.println("-----------------密钥协商-----------------");
        String aID = "AAAAAAAAAAAAA";
        SM2KeyPair aKeyPair = SM2.generateKeyPair();
        SM2.KeyExchange aKeyExchange = new SM2.KeyExchange(aID,aKeyPair);

        String bID = "BBBBBBBBBBBBB";
        SM2KeyPair bKeyPair = SM2.generateKeyPair();
        SM2.KeyExchange bKeyExchange = new SM2.KeyExchange(bID,bKeyPair);
        TransportEntity entity1 = aKeyExchange.keyExchange_1();
        TransportEntity entity2 = bKeyExchange.keyExchange_2(entity1);
        TransportEntity entity3 = aKeyExchange.keyExchange_3(entity2);
        bKeyExchange.keyExchange_4(entity3);
    }

}
