package com.signetz.codetools;

import com.duangframework.kit.ToolsKit;
import com.signetz.codetools.utils.EncryptUtils;
import java.io.IOException;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * @Author: youyang
 * @Date: Create in 2020-03-10 16:58
 * @Description : 生成 MD5 + CPU序列号 + 硬盘序列号
 */

public class Main {

    public static final Logger logger = LoggerFactory.getLogger(Main.class);


    /**
     * 生成 MD5 + CPU序列号 + 硬盘序列号的加签后的字符串
     *
     * @param args
     */
    public static void main(String[] args) {

        // 获取cpu序列号
        String cpuSerialNumber = getCPUSerialNumber();
        // 获取 硬盘号
        String hardDiskSerialNumber = getHardDiskSerialNumber();

        //读取配置文件中的值
        ResourceBundle resource = ResourceBundle.getBundle("application");
        String md5 = resource.getString("md5");

        // 拼接 字符串结果
        String result = md5 + cpuSerialNumber + hardDiskSerialNumber;
        logger.info("MD5 + CPU序列号 + 硬盘序列号: " + result);

        // 封装 加签的数据结构
        String signed = EncryptUtils.countersign(result);
        Map<String, String> map = new HashMap<String, String>();
        map.put("result", result);
        map.put("signed", signed);
        // map转换成json串
        String jsonStr = ToolsKit.toJsonString(map);
        logger.info("加签后的字符串结果: " + jsonStr);
    }


    /**
     * 获取CPU序列号
     *
     * @return
     * @throws IOException
     */
    public static String getCPUSerialNumber() {

        String serial = "";
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"wmic", "cpu", "get", "ProcessorId"});

            process.getOutputStream().close();

            Scanner sc = new Scanner(process.getInputStream());

            String property = sc.next();

            serial = sc.next();

        } catch (IOException e) {
            throw new RuntimeException("获取CPU序列号失败");
        }
        return serial;
    }


    /**
     * 获取 硬盘序列号
     *
     * @return
     * @throws IOException
     * @throws InterruptedException
     */
    public static String getHardDiskSerialNumber() {
        String serial = "";
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"wmic", "path", "win32_physicalmedia", "get", "serialnumber"});

            process.getOutputStream().close();

            Scanner sc = new Scanner(process.getInputStream());

            String property = sc.next();

            serial = sc.next();

        } catch (Exception e) {
            throw new RuntimeException("获取硬盘序列号失败");
        }

        return serial;
    }


}
