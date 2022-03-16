package org.zz.gmhelper.test;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM4Util;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

public class SM4UtilTest extends GMBaseTest {

    @Test
    public void test_shawn() throws Exception {
        String miwen = "0ec4ab51fc30485ff72d2bda83075e78";
        String k = "fc2f0d38165df667";

        byte[] bytes = SM4Util.encrypt_ECB_Padding(k.getBytes(), "shawn".getBytes());
        //System.out.println(new String(bytes));
        int length = bytes.length;
        char[] chars = new char[length * 2];
        int index = 0;
        char[] arr = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        for (byte aByte : bytes) {
            short n = 0x0f;
            short m = (short) 0xf0;
            byte a = (byte) (aByte & n);
            byte b = (byte) ((aByte & m) >> 4);
            System.out.print(arr[b]);
            System.out.print(arr[a]);
        }

        System.out.println("");

        byte[] bytes1 = SM4Util.decrypt_ECB_Padding(k.getBytes(), bytes);
        System.out.println(new String(bytes1));

    }

    @Test
    public void test_ECB_encrypt_decrypt() throws Exception {

        //原文
        String name = "shawn";
        //秘钥字符串
        String key = "66633266306433383136356466363637";

        //加密，密文字节数组
        byte[] bytes = SM4Util.encrypt_ECB_Padding(ByteUtils.fromHexString(key), name.getBytes());
        //转16进制字符串
        String mi = ByteUtils.toHexString(bytes);
        System.out.println(mi);

        //解密，原文字节数组
        byte[] name_byte = SM4Util.decrypt_ECB_Padding(ByteUtils.fromHexString(key), ByteUtils.fromHexString(mi));
        System.out.println(new String(name_byte));

    }

    @Test
    public void test_CBC_encrypt_decrypt() throws Exception {

        //原文
        String name = "shawn";
        //秘钥字符串
        String key = "66633266306433383136356466363637";
        //向量字符串 , 这里随便取得
        String vector = "66633266306433383136356466363637";

        //加密，密文字节数组
        byte[] bytes = SM4Util.encrypt_CBC_Padding(ByteUtils.fromHexString(key), ByteUtils.fromHexString(vector), name.getBytes());
        //转16进制字符串
        String mi = ByteUtils.toHexString(bytes);
        System.out.println(mi);

        //解密，原文字节数组
        byte[] name_byte = SM4Util.decrypt_CBC_Padding(ByteUtils.fromHexString(key), ByteUtils.fromHexString(vector), ByteUtils.fromHexString(mi));
        System.out.println(new String(name_byte));

    }


    @Test
    public void testEncryptAndDecrypt() {
        try {
            byte[] key = SM4Util.generateKey();
            byte[] iv = SM4Util.generateKey();
            byte[] cipherText = null;
            byte[] decryptedData = null;

            cipherText = SM4Util.encrypt_ECB_NoPadding(key, SRC_DATA_16B);
            System.out.println("SM4 ECB NoPadding encrypt result:\n" + Arrays.toString(cipherText));
            decryptedData = SM4Util.decrypt_ECB_NoPadding(key, cipherText);
            System.out.println("SM4 ECB NoPadding decrypt result:\n" + Arrays.toString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA_16B)) {
                Assert.fail();
            }

            cipherText = SM4Util.encrypt_ECB_Padding(key, SRC_DATA);
            System.out.println("SM4 ECB Padding encrypt result:\n" + Arrays.toString(cipherText));
            decryptedData = SM4Util.decrypt_ECB_Padding(key, cipherText);
            System.out.println("SM4 ECB Padding decrypt result:\n" + Arrays.toString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }

            cipherText = SM4Util.encrypt_CBC_Padding(key, iv, SRC_DATA);
            System.out.println("SM4 CBC Padding encrypt result:\n" + Arrays.toString(cipherText));
            decryptedData = SM4Util.decrypt_CBC_Padding(key, iv, cipherText);
            System.out.println("SM4 CBC Padding decrypt result:\n" + Arrays.toString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }

            cipherText = SM4Util.encrypt_CBC_NoPadding(key, iv, SRC_DATA_16B);
            System.out.println("SM4 CBC NoPadding encrypt result:\n" + Arrays.toString(cipherText));
            decryptedData = SM4Util.decrypt_CBC_NoPadding(key, iv, cipherText);
            System.out.println("SM4 CBC NoPadding decrypt result:\n" + Arrays.toString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA_16B)) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testMac() throws Exception {
        byte[] key = SM4Util.generateKey();
        byte[] iv = SM4Util.generateKey();

        byte[] mac = SM4Util.doCMac(key, SRC_DATA_24B);
        System.out.println("CMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());

        mac = SM4Util.doGMac(key, iv, 16, SRC_DATA_24B);
        System.out.println("GMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());

        byte[] cipher = SM4Util.encrypt_CBC_NoPadding(key, iv, SRC_DATA_32B);
        byte[] cipherLast16 = Arrays.copyOfRange(cipher, cipher.length - 16, cipher.length);
        mac = SM4Util.doCBCMac(key, iv, null, SRC_DATA_32B);
        if (!Arrays.equals(cipherLast16, mac)) {
            Assert.fail();
        }
        System.out.println("CBCMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());

        cipher = SM4Util.encrypt_CBC_Padding(key, iv, SRC_DATA_32B);
        cipherLast16 = Arrays.copyOfRange(cipher, cipher.length - 16, cipher.length);
        mac = SM4Util.doCBCMac(key, iv, SRC_DATA_32B);
        if (!Arrays.equals(cipherLast16, mac)) {
            Assert.fail();
        }
        System.out.println("CBCMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());
    }
}
