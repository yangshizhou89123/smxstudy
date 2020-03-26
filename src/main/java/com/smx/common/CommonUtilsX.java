package com.smx.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class CommonUtilsX {

    /**
     * 判断字节数组是否全0
     *
     * @param buffer
     * @return
     */
    public static boolean allZero(byte[] buffer) {
        for (int i = 0; i < buffer.length; i++) {
            if (buffer[i] != 0)
                return false;
        }
        return true;
    }

    /**
     * 字节数组拼接
     *
     * @param params
     * @return
     */
    public static byte[] join(byte[]... params) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] res = null;
        try {
            for (int i = 0; i < params.length; i++) {
                baos.write(params[i]);
            }
            res = baos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return res;
    }
}
