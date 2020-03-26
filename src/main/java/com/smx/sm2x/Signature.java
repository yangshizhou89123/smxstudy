package com.smx.sm2x;

import java.math.BigInteger;

public class Signature {
    BigInteger r;
    BigInteger s;

    public Signature(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public String toString() {
        return r.toString(16) + "," + s.toString(16);
    }
}
