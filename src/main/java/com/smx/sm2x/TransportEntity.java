package com.smx.sm2x;

import org.bouncycastle.math.ec.ECPoint;

import java.io.Serializable;

/**
 * 传输实体类
 *
 * @author Potato
 *
 */
public class TransportEntity implements Serializable {
    final byte[] R; //R点
    final byte[] S; //验证S
    final byte[] Z; //用户标识
    final byte[] K; //公钥

    public TransportEntity(byte[] r, byte[] s, byte[] z, ECPoint pKey) {
        R = r;
        S = s;
        Z=z;
        K=pKey.getEncoded(false);
    }
}
