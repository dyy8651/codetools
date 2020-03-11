package com.signetz.codetools.utils;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.TypeReference;
import com.duangframework.exception.ServiceException;
import com.duangframework.kit.ToolsKit;
import com.signetz.seal.entity.device.Device;
import com.signetz.seal.utils.encrypt.AESUtils;
import com.signetz.seal.utils.encrypt.RSAUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


/**
 * @Author: youyang
 * @Date: 2019/11/21 16:05
 * @Description: 加密、解签（加签、解签）
 */
public class EncryptUtils {

    public static final Logger log = LoggerFactory.getLogger(EncryptUtils.class);
    // 获取项目路径内容
    private final static String CONTENTPATH = EncryptUtils.class.getClass().getResource("/").getPath();
    // 公钥文件路径（服务器）
    private final static String PUBLICPATH = CONTENTPATH + "rsa_public_key.pem";
    // 私钥文件路径
    // private final static String PRIVATEPATH = CONTENTPATH + "private.key";

    // 本地测试用 公钥文件路径
    // private final static String PUBLICPATH = CONTENTPATH + "rsa_public_key.pem".substring(1);
    private static File privateKeyPath = new File("F:/pem/rsa_private_key.pem");

    private static String publicKey;

    private static final String SIGNED = "signed";
    private static final String RESULT = "result";




    /**
     * 加密
     *
     * @param param
     * @return
     */
    public static String encrypt(String param) {

        Map<String, String> map = new HashMap<String, String>();
        // 得到随机数
        String random = getRandom();
        log.info("产生的随机数[{}]", random);
        // 用随机数给json串加密
        String encryptResult = AESUtils.encrypt(param, random);
        // RSA对AES密码用公钥加密
        try {
            // 获取本地文件的公钥
            String publicKeyStr = getPublicKey();
            // 将Base64编码后的公钥转换成PublicKey对象
            PublicKey publicKey = RSAUtils.string2PublicKey(publicKeyStr);
            // 用公钥加密
            byte[] publicEncrypt = RSAUtils.publicEncrypt(random.getBytes(), publicKey);
            // 加密后的内容Base64编码
            String byte2Base64 = RSAUtils.byte2Base64(publicEncrypt);

            map.put("aesPassword", byte2Base64);
            map.put("encryptResult", encryptResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("加密后的数据：" + ToolsKit.toJsonString(map));
        return ToolsKit.toJsonString(map);
    }


    /**
     * 解密
     * @param aesPassword
     * @param encryptResult
     * @return
     */
//     public static String decrypt(String aesPassword,String encryptResult){
//
//         // 私钥对aes密码解密
//         String aesDecryptResult = "";
//         try {
//             // 获取本地文件的私钥
//             String privateKeyStr = getPrivateKey();
//             // 将Base64编码后的私钥转换成PrivateKey对象
//             PrivateKey privateKey = RSAUtils.string2PrivateKey(privateKeyStr);
//             // 加密后AES密码的内容用Base64解码
//             byte[] base642Byte = RSAUtils.base642Byte(aesPassword);
//             // 用私钥解密
//             byte[] privateDecrypt = RSAUtils.privateDecrypt(base642Byte, privateKey);
//             aesDecryptResult = new String(privateDecrypt);
//             // 解密后的aes密码
//             log.info("解密后AES密码[{}]", aesDecryptResult);
//         } catch (Exception e) {
//             e.printStackTrace();
//         }
//         System.out.println(aesDecryptResult);
//         // aes密码解密得到明文数据
//         return AESUtils.decrypt(encryptResult,aesDecryptResult);
//     }


    /**
     * 获得公钥
     *
     * @return
     * @throws IOException
     * @throws CertificateException
     */
    public static String getPublicKey() throws IOException, CertificateException {
        System.out.println(PUBLICPATH);
        if (EncryptUtils.publicKey == null || "".equals(EncryptUtils.publicKey)) {
            InputStream inStream = new FileInputStream(PUBLICPATH);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int ch;
            while ((ch = inStream.read()) != -1) {
                out.write(ch);
            }
            String publicKey = out.toString();
            // 去掉首尾多余的内容
            EncryptUtils.publicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replace("\n", "")
                    .replace("\r", "");
        }
        return EncryptUtils.publicKey;
    }


    /**
     * 获得私钥
     *
     * @return
     * @throws IOException
     * @throws CertificateException
     */
    public static String getPrivateKey() throws IOException, CertificateException {
        // System.out.println(CONTENTPATH);
        //  String privatePath = CONTENTPATH.replace(CONTENT,PRIVATEPATH);
        InputStream inStream = new FileInputStream(privateKeyPath);
        // InputStream inStream = new FileInputStream(PRIVATEPATH);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int ch;
        while ((ch = inStream.read()) != -1) {
            out.write(ch);
        }
        String privateKeyStr = out.toString();
        // 去掉首尾多余内容
        privateKeyStr = privateKeyStr.replace("-----BEGIN PRIVATE KEY-----\n", "").replace("\n-----END PRIVATE KEY-----", "");
        return privateKeyStr;
    }


    /**
     * 私钥加签
     *
     * @param resultMsg
     * @return byte[]
     */
    public static String countersign(String resultMsg) {

        String signStr = "";
        try {
            PrivateKey privateKey = RSAUtils.string2PrivateKey(getPrivateKey());
            Signature signature = Signature.getInstance("Sha1WithRSA");
            signature.initSign(privateKey);
            signature.update(resultMsg.getBytes("UTF-8"));
            byte[] signed = signature.sign();
            signStr = Base64.getEncoder().encodeToString(signed);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return signStr;
    }


    /**
     * 公钥解签
     *
     * @param resultMsg
     * @return Boolean
     */
    public static Boolean soulutionSign(String signedStr, String resultMsg) {

        boolean verify = false;
        byte[] signed = Base64.getDecoder().decode(signedStr);
        try {
            // 获取文件公钥将Base64编码后的公钥转换成PublicKey对象
            PublicKey publicKey = RSAUtils.string2PublicKey(getPublicKey());
            Signature signature2 = Signature.getInstance("Sha1WithRSA");
            signature2.initVerify(publicKey);
            signature2.update(resultMsg.getBytes("UTF-8"));
            verify = signature2.verify(signed);
            // 解签
            if (verify) {
                log.info("订阅消息后验签结果[{}]", verify);
                return true;
            }
        } catch (Exception e) {
            log.info("验签失败！请检查公钥的正确性！");
            e.printStackTrace();
        }
        return verify;
    }


    /**
     * 生成随机数
     *
     * @param
     * @return
     */
    public static String getRandom() {
        String string = "1234567890";
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 6; i++) {
            int index = (int) Math.floor(Math.random() * string.length());// 向下取整0-25
            sb.append(string.charAt(index));
        }
        return sb.toString();
    }


}
