package com.test;

import com.smx.sm3.SM3Utils;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

public class SM3Test {

    /**
     * 测试验签
     * @throws UnsupportedEncodingException
     */
    @Test
    public  void testEncrypt() throws UnsupportedEncodingException {
        String json = "aaaa";
        String encrypt = SM3Utils.encrypt(json);
        System.out.println("result:" + encrypt);
    }



}
