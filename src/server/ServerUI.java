package server;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import java.security.interfaces.*;
import java.math.BigInteger;

class ServerUI extends JFrame {

    //ServerUI构造函数
    public ServerUI() {
        super("服务器端_基于安全的即时聊天");
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        initMsgShowPanel();//调用初始化消息显示面板函数
        initMsgEditPanel();//调用初始化消息编辑面板函数

        Container pane = getContentPane();
        pane.setLayout(new BorderLayout());
        pane.add(msgShowPanel, BorderLayout.CENTER);
        pane.add(msgEditPanel, BorderLayout.SOUTH);
        pack();
        setVisible(true);

        try {
            serverKeyRSA = new SKey_RSA();//生成服务器端RSA密钥
            SKey_DES skeyDES = new SKey_DES();
            keyDES = skeyDES.getSecretKey();//生成DES密钥
            serverMsg = new ServerSocket(msgPort);//通信端口
            serverRSA = new ServerSocket(RSAPort);//RSA钥匙传递端口
            serverDES = new ServerSocket(DESPort);//DES密钥传递端口
            new keyThread(serverRSA.accept(), serverDES.accept()).start();
            new recThread(serverMsg.accept()).start();//启动接收监听线程
        } catch (Exception e) {
            System.out.println("server.accept:" + e);
        }

    }

    class keyThread extends Thread {//接收密钥线程

        private ObjectOutputStream ObjOSDES;
        private ObjectOutputStream ObjOSRSA;
        private ObjectInputStream ObjISRSA;
        byte[] keyDESbyte;

        public keyThread(Socket sRSA, Socket sDES) throws IOException {
            ObjOSDES = new ObjectOutputStream(sDES.getOutputStream());//DES密钥的输出流
            ObjOSRSA = new ObjectOutputStream(sRSA.getOutputStream());//服务器端的RSA公钥输出流
            ObjISRSA = new ObjectInputStream(sRSA.getInputStream());//接收客户端的RSA公钥输入流
        }

        public void run() {
            try {
                clientPBK = (RSAPublicKey) ObjISRSA.readObject();

                ObjOSRSA.writeObject(serverKeyRSA.getPublicKey());
                ObjOSRSA.flush();
                ObjOSRSA.close();
                ObjISRSA.close();

                keyDESbyte = SKey_RSA.wrapkey(keyDES, clientPBK);
                ObjOSDES.writeObject(keyDESbyte);
                ObjOSDES.flush();
                ObjOSDES.close();

                msgShowArea.append("服务器私钥：" + byteToBinary(serverKeyRSA.getPrivateKey().getEncoded()) + "\n");
                msgShowArea.append("服务器公钥：" + byteToBinary(serverKeyRSA.getPublicKey().getEncoded()) + "\n");
                msgShowArea.append("客户端公钥：" + byteToBinary(clientPBK.getEncoded()) + "\n");
                msgShowArea.append("DES密钥：" + byteToBinary(keyDES.getEncoded()) + "\n");
                msgShowArea.setCaretPosition(msgShowArea.getText().length());
            } catch (Exception e) {
                System.out.println("keyThread:" + e);
            }
        }
    }

    class recThread extends Thread {//接收信息线程

        private byte[] eData;
        private byte[] data;
        private byte[] eSData;
        private byte[] sData;
        private String str;

        public recThread(Socket c) throws IOException {//线程构造函数
            ObjOSMsg = new ObjectOutputStream(c.getOutputStream());//why要先建立outputStream?
            ObjISMsg = new ObjectInputStream(c.getInputStream());//创建输入流
        }

        public void run() {//线程监听函数
            try {
                while (true) {
                    eData = (byte[]) ObjISMsg.readObject();
                    data = SKey_DES.SEnc(keyDES, "DEC", eData);
                    str = new String(data);
                    eSData = (byte[]) ObjISMsg.readObject();
                    sData = SKey_DES.SEnc(keyDES, "DEC", eSData);
                    if (!Sign_n_Check.CheckSign(clientPBK, data, sData)) {
                        str = "信息验证错误。";
                    }
                    msgShowArea.append("Client: " + str + "\n");
                    if (detailShow.isSelected()) {
                        msgShowArea.append("接收到的加密信息：" + byteToBinary(eData) + "\n");
                        msgShowArea.append("接收到的加密签名：" + byteToBinary(eSData) + "\n");
                        msgShowArea.append("MD5WithRSA签名信息：" + byteToBinary(sData) + "\n");
                    }
                    msgShowArea.setCaretPosition(msgShowArea.getText().length());
                }
            } catch (Exception e) {
                System.out.println("消息接收错误：" + e);
            }
            ;
        }
    }

    /**
     * 初始化消息显示面板
     */
    private void initMsgShowPanel() {
        msgShowPanel = new JPanel();
        msgShowPanel.setLayout(new BorderLayout());

        JLabel label = new JLabel("消息显示: ");
        label.setFont(font);

        msgShowArea = new JTextArea(10, 50);
        msgShowArea.setEditable(false);
        msgShowArea.setLineWrap(true);

        JScrollPane msgShowPane = new JScrollPane();
        msgShowPane.setViewportView(msgShowArea);

        msgShowPanel.add(label, BorderLayout.NORTH);
        msgShowPanel.add(msgShowPane, BorderLayout.CENTER);
    }

    /**
     * 初始化消息编辑面板
     */
    private void initMsgEditPanel() {
        msgEditPanel = new JPanel();
        msgEditPanel.setLayout(new BorderLayout());

        JLabel label = new JLabel("消息编辑: ");
        label.setFont(font);

        msgEditArea = new JTextArea(5, 50);
        msgEditArea.setLineWrap(true);
        JScrollPane msgEditPane = new JScrollPane();
        msgEditPane.setViewportView(msgEditArea);

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout());

        JButton sendButton = new JButton("发送");
        sendButton.setFont(font);
        sendButton.addActionListener(new ActionListener() {

            public void actionPerformed(ActionEvent e) {//发送消息
                try {
                    byte[] data = msgEditArea.getText().getBytes();
                    byte[] sData = Sign_n_Check.Sign(serverKeyRSA.getPrivateKey(), data);
                    byte[] eData = SKey_DES.SEnc(keyDES, "ENC", data);
                    byte[] eSData = SKey_DES.SEnc(keyDES, "ENC", sData);

                    ObjOSMsg.writeObject(eData);//发送加密后的消息
                    ObjOSMsg.flush();
                    ObjOSMsg.writeObject(eSData);//发送加密后的签名
                    ObjOSMsg.flush();
                    msgShowArea.append("Server: " + msgEditArea.getText() + "\n");
                    if (detailShow.isSelected()) {
                        msgShowArea.append("加密后的信息：" + byteToBinary(eData) + "\n");
                        msgShowArea.append("MD5WithRSA签名信息：" + byteToBinary(sData) + "\n");
                        msgShowArea.append("加密后的签名：" + byteToBinary(eSData) + "\n");
                    }
                    msgShowArea.setCaretPosition(msgShowArea.getText().length());
                    msgEditArea.setText(null);
                } catch (Exception b) {
                    System.out.println("消息发送错误:" + b);
                }
                ;
            }
        });
        buttonPanel.add(sendButton);
        detailShow = new JCheckBox("显示加解密信息");
        buttonPanel.add(detailShow);

        msgEditPanel.add(label, BorderLayout.NORTH);
        msgEditPanel.add(msgEditPane, BorderLayout.CENTER);
        msgEditPanel.add(buttonPanel, BorderLayout.SOUTH);
    }

    /**
     * 字节数组转换为字符串表示的二进制数
     */
    private static String byteToBinary(byte[] bytes) {
        BigInteger bi = new BigInteger(bytes);
        return bi.toString(2);
    }

    private JPanel msgShowPanel;
    private JTextArea msgShowArea;
    private JPanel msgEditPanel;//
    private JTextArea msgEditArea;
    private JCheckBox detailShow;
    private ServerSocket serverMsg, serverRSA, serverDES;
    private static final int msgPort = 11268;
    private static final int RSAPort = 11234;
    private static final int DESPort = 11233;
    private ObjectInputStream ObjISMsg;
    private ObjectOutputStream ObjOSMsg;
    private SKey_RSA serverKeyRSA;/*服务端密钥*/

    private PublicKey clientPBK;/*客户端公钥*/

    private SecretKey keyDES;/*DES密钥*/

    private Font font = new Font("Dialog", Font.BOLD, 18);
}

class tester {
    public static void main(String[] args) {
        new ServerUI();
    }
}    