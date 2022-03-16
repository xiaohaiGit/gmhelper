package org.zz.gmhelper.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.engines.SM2Engine.Mode;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.test.util.FileUtil;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class SM2UtilTest extends GMBaseTest {

    @Test
    public void testSignAndVerify() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                    + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

            byte[] sign = SM2Util.sign(priKey, WITH_ID, SRC_DATA);
            System.out.println("SM2 sign with withId result:\n" + ByteUtils.toHexString(sign));
            byte[] rawSign = SM2Util.decodeDERSM2Sign(sign);
            sign = SM2Util.encodeSM2SignToDER(rawSign);
            System.out.println("SM2 sign with withId result:\n" + ByteUtils.toHexString(sign));
            boolean flag = SM2Util.verify(pubKey, WITH_ID, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }

            sign = SM2Util.sign(priKey, SRC_DATA);
            System.out.println("SM2 sign without withId result:\n" + ByteUtils.toHexString(sign));
            flag = SM2Util.verify(pubKey, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testEncryptAndDecrypt() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                    + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

            byte[] encryptedData = SM2Util.encrypt(pubKey, SRC_DATA_24B);
            System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(encryptedData));
            byte[] decryptedData = SM2Util.decrypt(priKey, encryptedData);
            System.out.println("SM2 decrypt result:\n" + ByteUtils.toHexString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA_24B)) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testEncryptAndDecrypt_C1C2C3() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                    + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

            byte[] encryptedData = SM2Util.encrypt(Mode.C1C3C2, pubKey, SRC_DATA_48B);
            System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(encryptedData));
            byte[] decryptedData = SM2Util.decrypt(Mode.C1C3C2, priKey, encryptedData);
            System.out.println("SM2 decrypt result:\n" + ByteUtils.toHexString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA_48B)) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void shawn_test() throws Exception {


        String pubKey = "04f2ea5b38a5b1658c406b60838a9e4ae4aec2543fda3c91c20ebd316c5b7ee6b10f39" +
                "158cd6503452536913ff003da61d3eb480129b42affd08b08c7ab6cf814d";
        String priKey = "adb2ac044410d70ec1b75f92233dcc0583cf4de86e1ceb47faa69fc6a58a1a74";
        String mi = "492e3f14f1af4738b49dba3b0cbaa2f6909361e72d56d85d0340b7bf85e641e15a8030909258699b4533a2b519" +
                "2cfd4196ccba8f8448ad7e769e6d51eff2dfd1b2e6509cf0f835611d8d4dfc14e4de19a5f0a9bf3f7455d551a15bd0" +
                "8affa902124959373f";
        String src = "shawn";

        //byte[] decrypt = UpSM2Util.decrypt(mi.getBytes(), priKey.getBytes());
        //System.out.println(new String(decrypt));

        byte[] encrypt = UpSM2Util.encrypt(src.getBytes(), pubKey.getBytes());
        System.out.println(new String(encrypt));


    }

    @Test
    public void shawn_test2() throws NoSuchAlgorithmException, UnsupportedEncodingException {

        // 注册BouncyCastle:
        Security.addProvider(new BouncyCastleProvider());
        // 按名称正常调用:
        MessageDigest md = MessageDigest.getInstance("SM2");
        md.update("HelloWorld".getBytes("UTF-8"));
        byte[] result = md.digest();
        System.out.println(new BigInteger(1, result).toString(16));

    }


    @Test
    public void testKeyPairEncoding() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] priKeyPkcs8Der = BCECUtil.convertECPrivateKeyToPKCS8(priKey, pubKey);
            System.out.println("private key pkcs8 der length:" + priKeyPkcs8Der.length);
            System.out.println("private key pkcs8 der:" + ByteUtils.toHexString(priKeyPkcs8Der));
            FileUtil.writeFile("target/ec.pkcs8.pri.der", priKeyPkcs8Der);

            String priKeyPkcs8Pem = BCECUtil.convertECPrivateKeyPKCS8ToPEM(priKeyPkcs8Der);
            FileUtil.writeFile("target/ec.pkcs8.pri.pem", priKeyPkcs8Pem.getBytes("UTF-8"));
            byte[] priKeyFromPem = BCECUtil.convertECPrivateKeyPEMToPKCS8(priKeyPkcs8Pem);
            if (!Arrays.equals(priKeyFromPem, priKeyPkcs8Der)) {
                throw new Exception("priKeyFromPem != priKeyPkcs8Der");
            }

            BCECPrivateKey newPriKey = BCECUtil.convertPKCS8ToECPrivateKey(priKeyPkcs8Der);

            byte[] priKeyPkcs1Der = BCECUtil.convertECPrivateKeyToSEC1(priKey, pubKey);
            System.out.println("private key pkcs1 der length:" + priKeyPkcs1Der.length);
            System.out.println("private key pkcs1 der:" + ByteUtils.toHexString(priKeyPkcs1Der));
            FileUtil.writeFile("target/ec.pkcs1.pri", priKeyPkcs1Der);

            byte[] pubKeyX509Der = BCECUtil.convertECPublicKeyToX509(pubKey);
            System.out.println("public key der length:" + pubKeyX509Der.length);
            System.out.println("public key der:" + ByteUtils.toHexString(pubKeyX509Der));
            FileUtil.writeFile("target/ec.x509.pub.der", pubKeyX509Der);

            String pubKeyX509Pem = BCECUtil.convertECPublicKeyX509ToPEM(pubKeyX509Der);
            FileUtil.writeFile("target/ec.x509.pub.pem", pubKeyX509Pem.getBytes("UTF-8"));
            byte[] pubKeyFromPem = BCECUtil.convertECPublicKeyPEMToX509(pubKeyX509Pem);
            if (!Arrays.equals(pubKeyFromPem, pubKeyX509Der)) {
                throw new Exception("pubKeyFromPem != pubKeyX509Der");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testSM2KeyRecovery() {
        try {
            String priHex = "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D";
            String xHex = "FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913";
            String yHex = "F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956";
            String encodedPubHex = "04FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956";
            String signHex = "30450220213C6CD6EBD6A4D5C2D0AB38E29D441836D1457A8118D34864C247D727831962022100D9248480342AC8513CCDF0F89A2250DC8F6EB4F2471E144E9A812E0AF497F801";
            byte[] signBytes = ByteUtils.fromHexString(signHex);
            byte[] src = ByteUtils.fromHexString("0102030405060708010203040506070801020304050607080102030405060708");
            byte[] withId = ByteUtils.fromHexString("31323334353637383132333435363738");

            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                    new BigInteger(ByteUtils.fromHexString(priHex)), SM2Util.DOMAIN_PARAMS);
            ECPublicKeyParameters pubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);

            if (!SM2Util.verify(pubKey, src, signBytes)) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testSM2KeyGen2() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                    + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testEncodeSM2CipherToDER() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            String src = "shawn";
            byte[] bytes = BCECUtil.convertECPrivateKeyToPKCS8(priKey, pubKey);
            //String s = BCECUtil.convertECPrivateKeyPKCS8ToPEM(bytes);
            BCECPrivateKey bcecPrivateKey = BCECUtil.convertPKCS8ToECPrivateKey(bytes);


            //byte[] encryptedData = SM2Util.encrypt(pubKey, SRC_DATA);
            // pubkey 加密
            byte[] encryptedData = SM2Util.encrypt(pubKey, src.getBytes());
            FileUtil.writeFile("target/encryptedCipher.dat", encryptedData);
            System.out.println(" shawn :" + ByteUtils.toHexString(encryptedData).toUpperCase());

            byte[] derCipher = SM2Util.encodeSM2CipherToDER(encryptedData);
            FileUtil.writeFile("target/derCipher.dat", derCipher);
            System.out.println(" shawn 2 :" + ByteUtils.toHexString(derCipher).toUpperCase());

            //byte[] decryptedData = SM2Util.decrypt(priKey, SM2Util.decodeDERSM2Cipher(derCipher));
            // prikey 解密
            byte[] decryptedData = SM2Util.decrypt(priKey, encryptedData);
            if (!Arrays.equals(decryptedData, src.getBytes())) {
                Assert.fail();
            }

            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void test_decrypt_ok() throws Exception {

        //原文
        String name = "shawn";
        //密文
        //注意，从js 或者 c++ 生成的密文前面如果没有04 都需要加上04
        String mi = "04492e3f14f1af4738b49dba3b0cbaa2f6909361e72d56d85d0340b7bf85e641e15a8030909258699b4533a2b5192cfd4196ccba8f8448ad7e769e6d51eff2dfd1b2e6509cf0f835611d8d4dfc14e4de19a5f0a9bf3f7455d551a15bd08affa902124959373f";
        //私钥
        String priKeyStr = "adb2ac044410d70ec1b75f92233dcc0583cf4de86e1ceb47faa69fc6a58a1a74";

        //通过私钥字符串生成私钥，有两种方式，如下
        //ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(new BigInteger(1,ByteUtils.fromHexString(priKeyStr)), SM2Util.DOMAIN_PARAMS);
        ECPrivateKeyParameters priKey = BCECUtil.createECPrivateKeyParameters(priKeyStr, SM2Util.DOMAIN_PARAMS);
        //通过私钥进行解密
        byte[] decrypt = SM2Util.decrypt(priKey, ByteUtils.fromHexString(mi));

        //判断解密后的密文和原文是否相同
        if (!Arrays.equals(decrypt, name.getBytes())) {
            Assert.fail();
        }
    }

    @Test
    public void test_encrypt1_ok() throws Exception {

        //原文
        String name = "shawn";
        //私钥字符串
        String priKeyStr = "adb2ac044410d70ec1b75f92233dcc0583cf4de86e1ceb47faa69fc6a58a1a74";
        //先创建私钥
        ECPrivateKeyParameters priKey = BCECUtil.createECPrivateKeyParameters(priKeyStr, SM2Util.DOMAIN_PARAMS);
        //通过使钥构建公钥
        ECPublicKeyParameters pubKey = BCECUtil.buildECPublicKeyByPrivateKey(priKey);

        //通过公钥将原文加密，生成字节数组
        byte[] encrypt = SM2Util.encrypt(pubKey, name.getBytes());
        //字节数组转成16进制字符串
        //注意：从 java 生成的密文前会多一个04 ，传给js 或者 c++ 时候，需要将04去掉
        String mi = ByteUtils.toHexString(encrypt);
        System.out.println(mi);
    }

    @Test
    public void test_encrypt2_ok() throws Exception {

        //原文
        String name = "shawn";
        //公钥字符串
        String pubKeyStr = "04f2ea5b38a5b1658c406b60838a9e4ae4aec2543fda3c91c20ebd316c5b7ee6b10f39158cd6503452536913ff003da61d3eb480129b42affd08b08c7ab6cf814d";
        //将公钥去头04，再对半拆分
        String x = "f2ea5b38a5b1658c406b60838a9e4ae4aec2543fda3c91c20ebd316c5b7ee6b1";
        String y = "0f39158cd6503452536913ff003da61d3eb480129b42affd08b08c7ab6cf814d";
        //创建公钥
        ECPublicKeyParameters pubKey = BCECUtil.createECPublicKeyParameters(x, y, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);

        //通过公钥将原文加密，生成字节数组
        byte[] encrypt = SM2Util.encrypt(pubKey, name.getBytes());
        //字节数组转成16进制字符串
        //注意：从 java 生成的密文前会多一个04 ，传给js 或者 c++ 时候，需要将04去掉
        String mi = ByteUtils.toHexString(encrypt);
        System.out.println(mi);
    }


    @Test
    public void testEncodeSM2CipherToDERForLoop() {
        try {
            for (int i = 0; i < 1000; ++i) {
                AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
                ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
                ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

                byte[] encryptedData = SM2Util.encrypt(pubKey, SRC_DATA);

                byte[] derCipher = SM2Util.encodeSM2CipherToDER(encryptedData);

                byte[] decryptedData = SM2Util.decrypt(priKey, SM2Util.decodeDERSM2Cipher(derCipher));
                if (!Arrays.equals(decryptedData, SRC_DATA)) {
                    Assert.fail();
                }
            }
            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testEncodeSM2CipherToDER_C1C2C3() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] encryptedData = SM2Util.encrypt(Mode.C1C2C3, pubKey, SRC_DATA);

            byte[] derCipher = SM2Util.encodeSM2CipherToDER(Mode.C1C2C3, encryptedData);
            FileUtil.writeFile("target/derCipher_c1c2c3.dat", derCipher);

            byte[] decryptedData = SM2Util.decrypt(Mode.C1C2C3, priKey, SM2Util.decodeDERSM2Cipher(Mode.C1C2C3, derCipher));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }

            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testGenerateBCECKeyPair() {
        try {
            KeyPair keyPair = SM2Util.generateKeyPair();
            ECPrivateKeyParameters priKey = BCECUtil.convertPrivateKeyToParameters((BCECPrivateKey) keyPair.getPrivate());
            ECPublicKeyParameters pubKey = BCECUtil.convertPublicKeyToParameters((BCECPublicKey) keyPair.getPublic());

            byte[] sign = SM2Util.sign(priKey, WITH_ID, SRC_DATA);
            boolean flag = SM2Util.verify(pubKey, WITH_ID, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }

            sign = SM2Util.sign(priKey, SRC_DATA);
            flag = SM2Util.verify(pubKey, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}
