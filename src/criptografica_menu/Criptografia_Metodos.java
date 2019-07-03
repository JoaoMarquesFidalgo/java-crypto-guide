/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package criptografica_menu;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sun.security.pkcs.PKCS8Key;

/**
 *
 * @author Asus
 */
public class Criptografia_Metodos {

    Scanner sc = new Scanner(System.in);

    //2.2.2
    public boolean guardar_chave() throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        //receber nome
        System.out.print("Escreva o nome do ficheiro no qual quer guardar a chave: ");
        String nome = sc.nextLine();

        //gerar chave
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        SecretKey sk = kg.generateKey();

        //criar ficheiro
        File ficheiro = new File(nome);
        FileOutputStream fos = new FileOutputStream(ficheiro);

        //gravar byte
        byte[] arraybites = sk.getEncoded();
        fos.write(arraybites);
        fos.close();
        System.out.println("Ficheiro escrito com sucesso");
        return true;
    }

    //2.2.3
    public boolean cifra_ficheiro_des() throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.print("Escreva o nome do ficheiro a cifrar: ");
        String nfac = sc.nextLine();
        //nome ficheiro a cifrar -> nfac
        System.out.print("Escreva o nome para o ficheiro cifrado: ");
        String nfc = sc.nextLine();
        //nome ficheiro cifrado -> nfc
        System.out.print("Escreva o nome do ficheiro para guardar a chave: ");
        String nfgc = sc.nextLine();
        //nome ficheiro guardar chave -> nfgc

        //passar ficheiro a array byte
        FileInputStream fis = new FileInputStream(nfac);
        byte[] b = new byte[fis.available()];
        fis.read(b);

        //criar key
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        SecretKey key = kg.generateKey();

        //cifrar
        Cipher cifra = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cifra.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytecifrado = cifra.doFinal(b);

        try {
            FileOutputStream NFC = new FileOutputStream(nfc);
            NFC.write(bytecifrado);
            NFC.close();

            FileOutputStream NFGC = new FileOutputStream(nfgc);
            NFGC.write(key.getEncoded());
            NFGC.close();
            System.out.println("Operações realizadas com sucesso");
        } catch (Exception e) {
            System.out.println("Erro: " + e.getMessage());
        }

        return true;
    }

    //2.2.4
    public boolean decifra_ficheiro_des() throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.print("Escreva o nome do ficheiro a decifrar: ");
        String nfad = sc.nextLine();
        //nome ficheiro a decifrar -> nfad
        System.out.print("Escreva o nome para o ficheiro decifrado: ");
        String nfd = sc.nextLine();
        //nome ficheiro decifrado -> nfd
        System.out.print("Escreva o nome do ficheiro que contem a chave: ");
        String nfc = sc.nextLine();
        //nome ficheiro chave -> nfc

        //buscar texto cifrado em bytes
        FileInputStream FC = new FileInputStream(nfad);
        byte[] FCifrado = new byte[FC.available()];
        FC.read(FCifrado);
        //FCifrado -> ficheiro cifrado

        //buscar chave
        FileInputStream chave = new FileInputStream(nfc);
        byte[] chavebytes = new byte[chave.available()];
        chave.read(chavebytes);
        SecretKey key = new SecretKeySpec(chavebytes, 0, chavebytes.length, "DES");
        //transformar o array de bytes com a chave numa nova class de SecretKey

        //decifrar e guardar no ficheiro
        Cipher cifra = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cifra.init(Cipher.DECRYPT_MODE, key);
        byte[] bytedecifrado = cifra.doFinal(FCifrado);
        FileOutputStream GFDecifrado = new FileOutputStream(nfd);
        GFDecifrado.write(bytedecifrado);
        GFDecifrado.close();
        //guardar 

        System.out.println("Operações realizadas com sucesso");

        return true;
    }

    //2.2.5
    public boolean cifra_AES() throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        System.out.print("Escreva o nome do ficheiro a cifrar: ");
        String nfac = sc.nextLine();
        //nome ficheiro a cifrar -> nfac
        System.out.print("Escreva o nome para o ficheiro cifrado: ");
        String nfc = sc.nextLine();
        //nome ficheiro cifrado -> nfc
        System.out.print("Escreva o nome do ficheiro para guardar a chave: ");
        String nfgc = sc.nextLine();
        //nome ficheiro guardar chave -> nfgc
        System.out.print("Algoritmo, modo de cifra e padding (AES/CBC/PKCS5Padding): ");
        String ga = sc.nextLine();
        //guardar algoritmo
        System.out.print("Nome do ficheiro para guardar IV: ");
        String nfgiv = sc.nextLine();
        //nome ficheiro guardar IV

        //passar ficheiro a array byte
        FileInputStream fis = new FileInputStream("aes/" + nfac);
        byte[] b = new byte[fis.available()];
        fis.read(b);
        byte[] arrayb;

        //criar key
        String[] algoritmo = ga.split("/");
        if (algoritmo[0].equals("AES")) {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            SecretKey key = kg.generateKey();
            arrayb = key.getEncoded();

            //iv
            /*
            SecureRandom random = new SecureRandom();
            byte [] randbyte = new byte[16];
            random.nextBytes(randbyte);
            IvParameterSpec iv = new IvParameterSpec(randbyte);
             */
            Cipher cifra = Cipher.getInstance(ga);
            cifra.init(Cipher.ENCRYPT_MODE, key);
            byte[] bytecifrado = cifra.doFinal(b);
            byte[] iv = cifra.getIV();
            try {
                FileOutputStream NFC = new FileOutputStream("aes/" + nfc);
                NFC.write(bytecifrado);
                NFC.close();

                FileOutputStream NFGC = new FileOutputStream("aes/" + nfgc);
                NFGC.write(key.getEncoded());
                NFGC.close();

                FileOutputStream NFGIV = new FileOutputStream("aes/" + nfgiv);
                NFGIV.write(iv);
                NFGIV.close();
                System.out.println("Operações realizadas com sucesso");
            } catch (Exception e) {
                System.out.println("Erro: " + e.getMessage());
            }
            return true;
        } else {
            System.out.println("algoritmo incorreto - exemplo: AES");
            return false;
        }

    }

    public boolean decifra_AES() throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        System.out.print("Escreva o nome do ficheiro a decifrar: ");
        String nfad = sc.nextLine();
        //nome ficheiro a decifrar -> nfad
        System.out.print("Escreva o nome para o ficheiro decifrado: ");
        String nfd = sc.nextLine();
        //nome ficheiro decifrado -> nfd
        System.out.print("Escreva o nome do ficheiro que contem a chave: ");
        String nfc = sc.nextLine();
        //nome ficheiro chave -> nfc
        System.out.print("Escreva o nome do ficheiro do algoritmo: ");
        String nfa = sc.nextLine();
        //nome ficheiro algoritmo -> nfa
        System.out.print("Escreva o nome do ficheiro que contem a iv: ");
        String nfiv = sc.nextLine();
        //nome ficheiro iv -> nfiv

        //buscar texto cifrado em bytes
        FileInputStream FC = new FileInputStream("aes/" + nfad);
        byte[] FCifrado = new byte[FC.available()];
        FC.read(FCifrado);
        //FCifrado -> ficheiro cifrado

        //buscar chave
        FileInputStream chave = new FileInputStream("aes/" + nfc);
        byte[] chavebytes = new byte[chave.available()];
        chave.read(chavebytes);
        SecretKey key = new SecretKeySpec(chavebytes, "AES");
        //transformar o array de bytes com a chave numa nova class de SecretKey

        //buscar iv
        FileInputStream iv = new FileInputStream("aes/" + nfiv);
        byte[] ivbyte = new byte[iv.available()];
        iv.read(ivbyte);
        IvParameterSpec iv_ = new IvParameterSpec(ivbyte);

        //decifrar e guardar no ficheiro
        Cipher cifra = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cifra.init(Cipher.DECRYPT_MODE, key, iv_);
        byte[] bytedecifrado = cifra.doFinal(FCifrado);
        FileOutputStream GFDecifrado = new FileOutputStream("aes/" + nfd);
        GFDecifrado.write(bytedecifrado);
        GFDecifrado.close();
        //guardar 

        System.out.println("Operações realizadas com sucesso");

        return true;

    }

    //2.3.2
    public boolean cifra_decifra_cbc() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        FileInputStream fis = new FileInputStream("tux-large.bmp");
        FileOutputStream fos = new FileOutputStream("imagem/encriptadocbc.bmp");

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecretKey key = kg.generateKey();

        SecureRandom random = new SecureRandom();
        byte[] randbyte = new byte[16];
        random.nextBytes(randbyte);
        IvParameterSpec iv = new IvParameterSpec(randbyte);

        Cipher cifra = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cifra.init(Cipher.ENCRYPT_MODE, key, iv);

        CipherInputStream cipherIn = new CipherInputStream(fis, cifra);

        int i;
        while ((i = cipherIn.read()) != -1) {
            fos.write(i);
        }

        /*
        CipherOutputStream cos = new CipherOutputStream(fos, cifra);
        byte[] buff = new byte[1024];
        int read;
        while((read=fis.read(buff))!=-1){
                cos.write(buff,0,read);
        }*/
        fis.close();
        fos.close();
        cipherIn.close();

        System.out.println("correu 1 - encriptou");

        FileInputStream fis2 = new FileInputStream("imagem/encriptadocbc.bmp");
        FileOutputStream fop = new FileOutputStream("imagem/desencriptadocbc.bmp");
        cifra.init(Cipher.DECRYPT_MODE, key, iv);
        CipherInputStream cipherfora = new CipherInputStream(fis2, cifra);

        int j;
        while ((j = cipherfora.read()) != -1) {
            fop.write(j);
        }

        cipherfora.close();
        fis2.close();
        System.out.println("correu 2 - desencriptou");
        return true;

    }

    public boolean cifra_decifra_ecb() {
        try {
            FileInputStream fis = new FileInputStream("tux-large.bmp");
            FileOutputStream fos = new FileOutputStream("imagem/encriptadoecb.bmp");

            KeyGenerator kg = KeyGenerator.getInstance("AES");
            SecretKey key = kg.generateKey();

            Cipher cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cifra.init(Cipher.ENCRYPT_MODE, key);

            CipherInputStream cipherIn = new CipherInputStream(fis, cifra);

            int i;
            while ((i = cipherIn.read()) != -1) {
                fos.write(i);
            }

            fis.close();
            fos.close();
            cipherIn.close();

            System.out.println("correu 1");

            FileInputStream fis2 = new FileInputStream("imagem/encriptadoecb.bmp");
            FileOutputStream fop = new FileOutputStream("imagem/desencriptadoecb.bmp");
            cifra.init(Cipher.DECRYPT_MODE, key);
            CipherInputStream cipherfora = new CipherInputStream(fis2, cifra);

            int j;
            while ((j = cipherfora.read()) != -1) {
                fop.write(j);
            }

            cipherfora.close();
            fis2.close();
            System.out.println("correu 2");
            return true;
        } catch (Exception e) {
            System.out.println("erro: " + e.getMessage());
            return false;
        }

    }

    //2.3.3
    public boolean cifra_2_3_3() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        FileInputStream fis = new FileInputStream("tux-large.bmp");
        FileOutputStream fos = new FileOutputStream("2_3_3/encriptado.bmp");

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecretKey key = kg.generateKey();

        SecureRandom random = new SecureRandom();
        byte[] randbyte = new byte[16];
        random.nextBytes(randbyte);
        IvParameterSpec iv = new IvParameterSpec(randbyte);

        Cipher cifra = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cifra.init(Cipher.ENCRYPT_MODE, key, iv);

        CipherInputStream cipherIn = new CipherInputStream(fis, cifra);

        int i;
        while ((i = cipherIn.read()) != -1) {
            fos.write(i);
        }

        //guardar cenas
        FileOutputStream g_iv = new FileOutputStream("2_3_3/iv.txt");
        g_iv.write(iv.getIV());
        g_iv.close();
        FileOutputStream g_chave = new FileOutputStream("2_3_3/chave.txt");
        g_chave.write(key.getEncoded());
        g_chave.close();

        System.out.println("feito");
        return true;
    }

    public boolean decifra_2_3_3() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {

        FileInputStream fis2 = new FileInputStream("2_3_3/encriptado.bmp");
        byte[] FCifrado = new byte[fis2.available()];
        fis2.read(FCifrado);

        FileOutputStream fop = new FileOutputStream("2_3_3/desencriptado.bmp");

        FileInputStream chave = new FileInputStream("2_3_3/chave.txt");
        byte[] chavebytes = new byte[chave.available()];
        chave.read(chavebytes);
        SecretKey key = new SecretKeySpec(chavebytes, "AES");
        //transformar o array de bytes com a chave numa nova class de SecretKey

        //buscar iv
        FileInputStream iv = new FileInputStream("2_3_3/iv.txt");
        byte[] ivbyte = new byte[iv.available()];
        iv.read(ivbyte);
        IvParameterSpec iv_ = new IvParameterSpec(ivbyte);

        Cipher cifra = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cifra.init(Cipher.DECRYPT_MODE, key, iv_);
        byte[] bytedecifrado = cifra.doFinal(FCifrado);
        fop.write(bytedecifrado);
        fop.close();

        fis2.close();
        System.out.println("correu 2 - desencriptou");

        return true;
    }

    public boolean cifra_2_3_3_ecb() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        FileInputStream fis = new FileInputStream("tux-large.bmp");
        FileOutputStream fos = new FileOutputStream("2_3_3_ecb/encriptado.bmp");

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecretKey key = kg.generateKey();

        Cipher cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cifra.init(Cipher.ENCRYPT_MODE, key);

        CipherInputStream cipherIn = new CipherInputStream(fis, cifra);

        int i;
        while ((i = cipherIn.read()) != -1) {
            fos.write(i);
        }

        //guardar cenas
        FileOutputStream g_chave = new FileOutputStream("2_3_3_ecb/chave.txt");
        g_chave.write(key.getEncoded());
        g_chave.close();

        System.out.println("feito");
        return true;
    }

    public boolean decifra_2_3_3_ecb() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {

        FileInputStream fis2 = new FileInputStream("2_3_3_ecb/encriptado.bmp");
        byte[] FCifrado = new byte[fis2.available()];
        fis2.read(FCifrado);

        FileOutputStream fop = new FileOutputStream("2_3_3_ecb/desencriptado.bmp");

        FileInputStream chave = new FileInputStream("2_3_3_ecb/chave.txt");
        byte[] chavebytes = new byte[chave.available()];
        chave.read(chavebytes);
        SecretKey key = new SecretKeySpec(chavebytes, "AES");
        //transformar o array de bytes com a chave numa nova class de SecretKey

        Cipher cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cifra.init(Cipher.DECRYPT_MODE, key);
        byte[] bytedecifrado = cifra.doFinal(FCifrado);
        fop.write(bytedecifrado);
        fop.close();

        fis2.close();
        System.out.println("correu 2 - desencriptou");

        return true;
    }

    public boolean cifra_2_3_3_ofb() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        FileInputStream fis = new FileInputStream("tux-large.bmp");
        FileOutputStream fos = new FileOutputStream("2_3_3_ofb/encriptado.bmp");

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecretKey key = kg.generateKey();

        SecureRandom random = new SecureRandom();
        byte[] randbyte = new byte[16];
        random.nextBytes(randbyte);
        IvParameterSpec iv = new IvParameterSpec(randbyte);

        Cipher cifra = Cipher.getInstance("AES/OFB/PKCS5Padding");
        cifra.init(Cipher.ENCRYPT_MODE, key, iv);

        CipherInputStream cipherIn = new CipherInputStream(fis, cifra);

        int i;
        while ((i = cipherIn.read()) != -1) {
            fos.write(i);
        }

        //guardar cenas
        FileOutputStream g_iv = new FileOutputStream("2_3_3_ofb/iv.txt");
        g_iv.write(iv.getIV());
        g_iv.close();
        FileOutputStream g_chave = new FileOutputStream("2_3_3_ofb/chave.txt");
        g_chave.write(key.getEncoded());
        g_chave.close();

        System.out.println("feito");
        return true;
    }

    public boolean decifra_2_3_3_ofb() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {

        FileInputStream fis2 = new FileInputStream("2_3_3_ofb/encriptado.bmp");
        byte[] FCifrado = new byte[fis2.available()];
        fis2.read(FCifrado);

        FileOutputStream fop = new FileOutputStream("2_3_3_ofb/desencriptado.bmp");

        FileInputStream chave = new FileInputStream("2_3_3_ofb/chave.txt");
        byte[] chavebytes = new byte[chave.available()];
        chave.read(chavebytes);
        SecretKey key = new SecretKeySpec(chavebytes, "AES");
        //transformar o array de bytes com a chave numa nova class de SecretKey

        //buscar iv
        FileInputStream iv = new FileInputStream("2_3_3_ofb/iv.txt");
        byte[] ivbyte = new byte[iv.available()];
        iv.read(ivbyte);
        IvParameterSpec iv_ = new IvParameterSpec(ivbyte);

        Cipher cifra = Cipher.getInstance("AES/OFB/PKCS5Padding");
        cifra.init(Cipher.DECRYPT_MODE, key, iv_);
        byte[] bytedecifrado = cifra.doFinal(FCifrado);
        fop.write(bytedecifrado);
        fop.close();

        fis2.close();
        System.out.println("correu 2 - desencriptou");

        return true;
    }

    public boolean cifra_2_3_3_cfb() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        FileInputStream fis = new FileInputStream("tux-large.bmp");
        FileOutputStream fos = new FileOutputStream("2_3_3_cfb/encriptado.bmp");

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecretKey key = kg.generateKey();

        SecureRandom random = new SecureRandom();
        byte[] randbyte = new byte[16];
        random.nextBytes(randbyte);
        IvParameterSpec iv = new IvParameterSpec(randbyte);

        Cipher cifra = Cipher.getInstance("AES/CFB/PKCS5Padding");
        cifra.init(Cipher.ENCRYPT_MODE, key, iv);

        CipherInputStream cipherIn = new CipherInputStream(fis, cifra);

        int i;
        while ((i = cipherIn.read()) != -1) {
            fos.write(i);
        }

        //guardar cenas
        FileOutputStream g_iv = new FileOutputStream("2_3_3_cfb/iv.txt");
        g_iv.write(iv.getIV());
        g_iv.close();
        FileOutputStream g_chave = new FileOutputStream("2_3_3_cfb/chave.txt");
        g_chave.write(key.getEncoded());
        g_chave.close();

        System.out.println("feito");
        return true;
    }

    public boolean decifra_2_3_3_cfb() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {

        FileInputStream fis2 = new FileInputStream("2_3_3_cfb/encriptado.bmp");
        byte[] FCifrado = new byte[fis2.available()];
        fis2.read(FCifrado);

        FileOutputStream fop = new FileOutputStream("2_3_3_cfb/desencriptado.bmp");

        FileInputStream chave = new FileInputStream("2_3_3_cfb/chave.txt");
        byte[] chavebytes = new byte[chave.available()];
        chave.read(chavebytes);
        SecretKey key = new SecretKeySpec(chavebytes, "AES");
        //transformar o array de bytes com a chave numa nova class de SecretKey

        //buscar iv
        FileInputStream iv = new FileInputStream("2_3_3_cfb/iv.txt");
        byte[] ivbyte = new byte[iv.available()];
        iv.read(ivbyte);
        IvParameterSpec iv_ = new IvParameterSpec(ivbyte);

        Cipher cifra = Cipher.getInstance("AES/CFB/PKCS5Padding");
        cifra.init(Cipher.DECRYPT_MODE, key, iv_);
        byte[] bytedecifrado = cifra.doFinal(FCifrado);
        fop.write(bytedecifrado);
        fop.close();

        fis2.close();
        System.out.println("correu 2 - desencriptou");

        return true;
    }

    //2.3.4
    public boolean c2_3_4() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
        FileInputStream fis = new FileInputStream("2_3_4/textoclaro.txt");
        byte[] arrayb = new byte[fis.available()];
        fis.read(arrayb);

        KeyGenerator kg = KeyGenerator.getInstance("DES");
        SecretKey sk = kg.generateKey();

        Cipher cifra = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cifra.init(Cipher.ENCRYPT_MODE, sk);
        byte[] cifrado = cifra.doFinal(arrayb);

        FileOutputStream fos = new FileOutputStream("2_3_4/cifrado.txt");
        fos.write(cifrado);
        fos.close();

        FileOutputStream fos2 = new FileOutputStream("2_3_4/chave.txt");
        fos2.write(sk.getEncoded());
        fos2.close();
        fis.close();
        System.out.println("feito");
        return true;
    }

    public boolean d2_3_4() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
        FileInputStream fis = new FileInputStream("2_3_4/cifrado.txt");
        byte[] FCifrado = new byte[fis.available()];
        fis.read(FCifrado);

        FileOutputStream fop = new FileOutputStream("2_3_4/desencriptado.txt");

        FileInputStream chave = new FileInputStream("2_3_4/chave.txt");
        byte[] chavebytes = new byte[chave.available()];
        chave.read(chavebytes);
        SecretKey key = new SecretKeySpec(chavebytes, "DES");

        Cipher cifra = Cipher.getInstance("DES/ECB/NoPadding");
        cifra.init(Cipher.DECRYPT_MODE, key);
        byte[] arrayb = cifra.doFinal(FCifrado);
        fop.write(arrayb);
        fop.close();
        fis.close();

        System.out.println("feito");
        return true;
        //no texto de decifra, é adicionado simbolos especiais devido ao nopadding
    }

    public boolean g_c_assimetrica() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("Escreva o nome para guardar a chave publica");
        String gpubk = sc.nextLine();
        System.out.println("Escreva o nome para guardar chave privada");
        String gprivk = sc.nextLine();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();
        PublicKey pubk = kp.getPublic();
        PrivateKey privk = kp.getPrivate();

        FileOutputStream fos = new FileOutputStream("rsa/" + gpubk);
        fos.write(pubk.getEncoded());
        fos.close();
        fos = new FileOutputStream("rsa/" + gprivk);
        fos.write(privk.getEncoded());
        fos.close();

        System.out.println("guardou");
        return true;
    }

    public boolean cifrar_rsa() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        //pede e guarda
        FileInputStream fis = new FileInputStream("rsa2/textoclaro.txt");
        byte[] FaCifrar = new byte[fis.available()];
        fis.read(FaCifrar);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pubKey = kp.getPublic();
        PrivateKey privk = kp.getPrivate();

        /*
        X509EncodedKeySpec spec1 = new X509EncodedKeySpec(FaCifrar);
        KeyFactory kf1 = KeyFactory.getInstance("RSA");
        PublicKey pubKey = kf1.generatePublic(spec1);
        PrivateKey privk = kf1.generatePrivate(spec1);
         */
        //X509EncodedKeySpec x509encoded = new X509EncodedKeySpec(pubk.getEncoded());
        //codifica com a chave publica
        Cipher cifra = Cipher.getInstance("RSA");
        cifra.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] bytecifrado = cifra.doFinal(FaCifrar);

        //guardar criptograma
        FileOutputStream fos = new FileOutputStream("rsa2/cifrado.txt");
        fos.write(bytecifrado);
        fos.close();

        //guardar chave
        fos = new FileOutputStream("rsa2/publica.txt");
        fos.write(pubKey.getEncoded());
        fos.close();
        fos = new FileOutputStream("rsa2/privada.txt");
        fos.write(privk.getEncoded());
        fos.close();

        System.out.println("feito");
        return true;
    }

    public boolean decifrar_rsa() {
        try {
            FileInputStream fis = new FileInputStream("rsa2/cifrado.txt");
            byte[] FCifrado = new byte[fis.available()];
            fis.read(FCifrado);
            fis.close();

            fis = new FileInputStream("rsa2/privada.txt");
            byte[] chave = new byte[fis.available()];
            fis.read(chave);

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(chave);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privk = kf.generatePrivate(spec);

            /*
            PrivateKey privk = (PrivateKey) new PKCS8EncodedKeySpec(chave);
            fis.close();
             */
            Cipher cifra = Cipher.getInstance("RSA");
            cifra.init(Cipher.DECRYPT_MODE, privk);
            byte[] bytecifrado = cifra.doFinal(FCifrado);

            FileOutputStream fos = new FileOutputStream("rsa2/decifrado_rsa.txt");
            fos.write(bytecifrado);
            fos.close();

            System.out.println("feito");
            return true;
        } catch (Exception e) {
            System.out.println("erro: " + e.getMessage());
        }
        return false;
    }

    public boolean cifra_hibrida() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        
        //mal
        /*
        FileInputStream fis = new FileInputStream("cifra2x/textoclaro.txt");
        byte[] FaCifrar = new byte[fis.available()];
        fis.read(FaCifrar);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pubKey = kp.getPublic();
        PrivateKey privk = kp.getPrivate();

        //codifica com a chave publica
        Cipher cifra = Cipher.getInstance("RSA");
        cifra.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] bytecifrado = cifra.doFinal(FaCifrar);

        //guardar criptograma
        FileOutputStream fos = new FileOutputStream("cifra2x/cifrado1.txt");
        fos.write(bytecifrado);
        fos.close();

        //guardou primeira cifra
        System.out.println("feito");

        //ir buscar texto cifrado
        fis = new FileInputStream("cifra2x/cifrado1.txt");
        byte[] Fcifrado = new byte[fis.available()];
        fis.read(Fcifrado);

        //cifrar por simetrica
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        SecretKey key = kg.generateKey();
        //cifrar
        cifra = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cifra.init(Cipher.ENCRYPT_MODE, key);
        bytecifrado = cifra.doFinal(Fcifrado);
        //guardar textocifrado em DES
        fos = new FileOutputStream("cifra2x/cifradodes.txt");
        fos.write(bytecifrado);
        fos.close();
        fos = new FileOutputStream("cifra2x/chavedes.txt");
        fos.write(key.getEncoded());
        fos.close();

        System.out.println("feito 2");

        //nao consegui cifrar 2x por RSA, mas deu para cifrar RSA+DES
        //guardar chave
        fos = new FileOutputStream("cifra2x/publica.txt");
        fos.write(pubKey.getEncoded());
        fos.close();
        fos = new FileOutputStream("cifra2x/privada.txt");
        fos.write(privk.getEncoded());
        fos.close();

        System.out.println("feito 3");
*/



        
        // correto

        /*
        Obtains Alice's public key.
        Generates a fresh symmetric key for the data encapsulation scheme.
        Encrypts the message under the data encapsulation scheme, using the symmetric key just generated.
        Encrypt the symmetric key under the key encapsulation scheme, using Alice's public key.
        Send both of these encryptions to Alice.
        */
        
        FileInputStream fis = new FileInputStream("cifra2x/textoclaro.txt");
        byte[] FaCifrar = new byte[fis.available()];
        fis.read(FaCifrar);

        //cifrar por simetrica
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecretKey key = kg.generateKey();
        //cifrar
        Cipher cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cifra.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytecifrado = cifra.doFinal(FaCifrar);
        
        FileOutputStream fos = new FileOutputStream("cifra2x/cifrado1x.txt");
        fos.write(bytecifrado);
        fos.close();
        
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        KeyPair kp = kpg.genKeyPair();
        PublicKey pubKey = kp.getPublic();
        PrivateKey privk = kp.getPrivate();

        //codifica com a chave publica
        cifra = Cipher.getInstance("RSA");
        cifra.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] bytecifrado2 = cifra.doFinal(key.getEncoded());
        
        fos = new FileOutputStream("cifra2x/cifrachave.txt");
        fos.write(bytecifrado2);
        fos.close();
        
        fos = new FileOutputStream("cifra2x/chavepublica.txt");
        fos.write(pubKey.getEncoded());
        fos.close();
        
        fos = new FileOutputStream("cifra2x/chaveprivada.txt");
        fos.write(privk.getEncoded());
        fos.close();
        return true;
    }

    public boolean decifra_hibrida() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        
        /*
        Uses her private key to decrypt the symmetric key contained in the key encapsulation segment.
        Uses this symmetric key to decrypt the message contained in the data encapsulation segment.
        */
        
        FileInputStream fis;
        fis = new FileInputStream("cifra2x/chaveprivada.txt");
        byte[] chavepr = new byte[fis.available()];
        fis.read(chavepr);
        fis.close();
        
        fis = new FileInputStream("cifra2x/cifrachave.txt");
        byte[] chaveAESc = new byte[fis.available()];
        fis.read(chaveAESc);
        fis.close();
        
        
        //decifrar chaveAES com chave privada da alice
        KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(chavepr));
        
        Cipher cifra = Cipher.getInstance("RSA");
        cifra.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytecifrado2 = cifra.doFinal(chaveAESc);
        //decifrei a chave aes com a chave privada da alice e vou desencriptar o textooriginal com o seu resultado
        
        
        //ir buscar chaveAES decifrada e fazer cast para Secretkey
        SecretKey key = new SecretKeySpec(bytecifrado2, 0, bytecifrado2.length, "AES");
        
        //decifrar texto original com chave de cima
        fis = new FileInputStream("cifra2x/cifrado1x.txt");
        byte[] texto = new byte[fis.available()];
        fis.read(texto);
        fis.close();
        
        cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cifra.init(Cipher.DECRYPT_MODE, key);
        byte[] bytedecifrado = cifra.doFinal(texto);
        
        FileOutputStream fos = new FileOutputStream("cifra2x/textodecifrado.txt");
        fos.write(bytedecifrado);
        fos.close();
        
        
        return true;
    }
    
    public boolean cifrar_2x_sym() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream("cifra2x_sym/textoclaro.txt");
        byte[] texto = new byte[fis.available()];
        fis.read(texto);
        fis.close();
        
        //cifrar 1x
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        SecretKey key = kg.generateKey();
        Cipher cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cifra.init(Cipher.ENCRYPT_MODE, key);
        byte[] textocifrado = cifra.doFinal(texto);
        
        //cifrar 2x
        KeyGenerator kg1 = KeyGenerator.getInstance("AES");
        SecretKey key1 = kg1.generateKey();
        cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cifra.init(Cipher.ENCRYPT_MODE, key1);
        byte[] textocifrado1 = cifra.doFinal(textocifrado);
        
        FileOutputStream fos = new FileOutputStream("cifra2x_sym/cifra1x.txt");
        fos.write(textocifrado);
        fos.close();
        
        fos = new FileOutputStream("cifra2x_sym/cifra2x.txt");
        fos.write(textocifrado1);
        fos.close();
        
        fos = new FileOutputStream("cifra2x_sym/chave1x.txt");
        fos.write(key.getEncoded());
        fos.close();
        
        fos = new FileOutputStream("cifra2x_sym/chave2x.txt");
        fos.write(key1.getEncoded());
        fos.close();
        
        System.out.println("feito");
        return true;
    }
    public boolean decifrar_2x_sym() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream("cifra2x_sym/cifra2x.txt");
        byte[] texto = new byte[fis.available()];
        fis.read(texto);
        fis.close();
        
        fis = new FileInputStream("cifra2x_sym/chave2x.txt");
        byte[] chave1 = new byte[fis.available()];
        fis.read(chave1);
        fis.close();
        
        fis = new FileInputStream("cifra2x_sym/chave1x.txt");
        byte[] chave2 = new byte[fis.available()];
        fis.read(chave2);
        fis.close();
        
        SecretKey key2x = new SecretKeySpec(chave1, 0, chave1.length, "AES");
        SecretKey key1x = new SecretKeySpec(chave2, 0, chave2.length, "AES");
        
        Cipher cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cifra.init(Cipher.DECRYPT_MODE, key2x);
        byte[] texto2x = cifra.doFinal(texto);
        
        cifra = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cifra.init(Cipher.DECRYPT_MODE, key1x);
        byte[] texto1x = cifra.doFinal(texto2x);
        
        FileOutputStream fos = new FileOutputStream("cifra2x_sym/dec1x.txt");
        fos.write(texto2x);
        fos.close();
        fos = new FileOutputStream("cifra2x_sym/dec2x.txt");
        fos.write(texto1x);
        fos.close();
        
        System.out.println("feito");
        return true;
    }
    
    public boolean sintese() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream("sintese/textoclaro.txt");
        byte[] texto = new byte[fis.available()];
        fis.read(texto);
        fis.close();
        
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digerido = md.digest(texto);
        
        FileOutputStream fos = new FileOutputStream("sintese/hashed.txt");
        fos.write(digerido);
        fos.close();
        return true;
    }
    
    public boolean sintese2() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream("sintese/hashed_sha2.txt");
        byte[] texto = new byte[fis.available()];
        fis.read(texto);
        fis.close();
        
        fis = new FileInputStream("sintese/hashed_md5.txt");
        byte[] texto2 = new byte[fis.available()];
        fis.read(texto2);
        fis.close();
        
        fis = new FileInputStream("sintese/hashed_sha1.txt");
        byte[] texto3 = new byte[fis.available()];
        fis.read(texto3);
        fis.close();
        
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digerido = md.digest(texto);
        
        MessageDigest md2 = MessageDigest.getInstance("MD5");
        byte[] digerido2 = md2.digest(texto2);
        
        MessageDigest md3 = MessageDigest.getInstance("SHA-1");
        byte[] digerido3 = md3.digest(texto3);
        
        FileOutputStream fos = new FileOutputStream("sintese/hashed_sha2_b.txt");
        fos.write(digerido);
        fos.close();
        
        fos = new FileOutputStream("sintese/hashed_md5_b.txt");
        fos.write(digerido2);
        fos.close();
        
        fos = new FileOutputStream("sintese/hashed_sha1_b.txt");
        fos.write(digerido3);
        fos.close();
        
        System.out.println("feito");
        
        return true;
    }
    
    public boolean sintese2_5_2() throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        FileInputStream fis = new FileInputStream("sintese/nomes.txt");
        byte[] texto = new byte[fis.available()];
        fis.read(texto);
        fis.close();
        
        //fazer hash
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digerido = md.digest(texto);
        
        MessageDigest md2 = MessageDigest.getInstance("MD5");
        byte[] digerido2 = md2.digest(texto);
        
        MessageDigest md3 = MessageDigest.getInstance("SHA-1");
        byte[] digerido3 = md3.digest(texto);
        
        //guardar hash
        FileOutputStream fos = new FileOutputStream("sintese/hashed_sha2.txt");
        fos.write(digerido);
        fos.close();
        
        fos = new FileOutputStream("sintese/hashed_md5.txt");
        fos.write(digerido2);
        fos.close();
        
        fos = new FileOutputStream("sintese/hashed_sha1.txt");
        fos.write(digerido3);
        fos.close();
        
        
        Random ran = new Random();
        int x = ran.nextInt(digerido.length);
        digerido[0] |= (byte) (1 << x);
        int y = ran.nextInt(digerido2.length);
        digerido2[0] |= (byte) (1 << y);
        int z = ran.nextInt(digerido3.length);
        digerido3[0] |= (byte) (1 << z);
        
        md = MessageDigest.getInstance("SHA-256");
        byte[] digerido4 = md.digest(digerido);
        
        md2 = MessageDigest.getInstance("MD5");
        byte[] digerido5 = md2.digest(digerido2);
        
        md3 = MessageDigest.getInstance("SHA-1");
        byte[] digerido6 = md3.digest(digerido3);
        
        //xor
        byte[] sha2 = new byte[digerido.length];
        int sha2_b = 0;
        for(int i = 0; i < digerido.length; i++){
            //isto ?
            sha2[i] = (byte)(digerido[i] ^ digerido4[i]);
            //isto ? 
            if((int) (digerido[i]^digerido4[i]) != 0){
                sha2_b++;
            }
        }
        byte[] md5 = new byte[digerido2.length];
        for(int i = 0; i < digerido2.length; i++){
            md5[i] = (byte)(digerido2[i] ^ digerido5[i]);
        }
        byte[] sha1 = new byte[digerido3.length];
        for(int i = 0; i < digerido3.length; i++){
            sha1[i] = (byte)(digerido3[i] ^ digerido6[i]);
        }
        
        
        //guardar hash alterada e numero de alteracoes
        fos = new FileOutputStream("sintese/hashed_sha2_b.txt");
        fos.write(digerido4);
        fos.close();
        fos = new FileOutputStream("sintese/hashed_sha2_n.txt");
        fos.write(sha2);
        fos.close();
        
        fos = new FileOutputStream("sintese/hashed_md5_b.txt");
        fos.write(digerido5);
        fos.close();
        fos = new FileOutputStream("sintese/hashed_md5_n.txt");
        fos.write(md5);
        fos.close();
        
        fos = new FileOutputStream("sintese/hashed_sha1_b.txt");
        fos.write(digerido6);
        fos.close();
        fos = new FileOutputStream("sintese/hashed_sha1_n.txt");
        fos.write(sha1);
        fos.close();
        
        System.out.println("feito");
        
        return true;
    }
}
