package com.smx.sm3;

import com.smx.common.CommonUtilsX;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Security;

public class SM3Utils {
    private static final String ENCODING = "UTF-8";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * sm3加密
     * @param src 原文
     * @return
     */
    public static String encrypt(String src) throws UnsupportedEncodingException {
        byte[] srcBytes = src.getBytes(ENCODING);
        byte[] encrypt = encrypt(srcBytes);
        return ByteUtils.toHexString(encrypt);
    }

    /**
     * sm3加密
     * @param srcBytes 原文字节
     * @return
     */
    public static byte[] encrypt(byte[] srcBytes){
        //sm3加密
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(srcBytes,0,srcBytes.length);
        byte[] result = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(result,0);
        return result;
    }


    /**
     *
     * @param key
     * @param srcData
     * @return
     */
    public static byte[] encryptByKey(byte[] key,byte[] srcData){
        KeyParameter keyParameter = new KeyParameter(key);
        SM3Digest sm3Digest = new SM3Digest();
        HMac hMac = new HMac(sm3Digest);
        hMac.init(keyParameter);
        hMac.update(srcData,0,srcData.length);
        byte[] result = new byte[hMac.getMacSize()];
        hMac.doFinal(result,0);
        return result;

    }


    /**
     * sm3摘要
     *
     * @param params
     * @return
     */
    public static byte[] encrypt(byte[]... params) {
        byte[] res = null;
        res = encrypt(CommonUtilsX.join(params));
        return res;
    }

}
