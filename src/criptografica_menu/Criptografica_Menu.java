/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package criptografica_menu;

import java.util.Scanner;
import criptografica_menu.Criptografia_Metodos;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Asus
 */
public class Criptografica_Menu {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, FileNotFoundException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        Criptografia_Metodos cripto = new Criptografia_Metodos();

        System.out.println("Olá, bem vindo ao meu programa para cifrar/decifrar documentos, para sair do programa digite 0");
        System.out.println("Escolha uma opção do menu: \n\t1 - Guardar chave DES num ficheiro\n\t"
                + "2 - Encriptar usando DES e guardar no ficheiro\n\t"
                + "3 - Desencriptar usando DES e guardar no ficheiro\n\t"
                + "4 - Encriptar usando AES\n\t"
                + "5 - Desencriptar usando AES\n\t"
                + "6 - cifrar imagem com cbc\n\t"
                + "7 - cifrar imagem com ebc\n\t"
                + "8 - cifrar 2.3.3\n\t"
                + "9 - decifrar 2.3.3\n\t");
        System.out.print("Opção: \t");
        Scanner sc = new Scanner(System.in);
        int valor = sc.nextInt();

        while (valor != 0) {
            if (valor == 1) {
                cripto.guardar_chave();
            } else if (valor == 2) {
                cripto.cifra_ficheiro_des();
            } else if (valor == 3) {
                cripto.decifra_ficheiro_des();
            }else if(valor == 4){
                cripto.cifra_AES();
            }else if(valor == 5){
                cripto.decifra_AES();
            }
            else if(valor == 6){
                cripto.cifra_decifra_cbc();
            }else if(valor == 7){
                cripto.cifra_decifra_ecb();
            }else if(valor == 8){
                cripto.cifra_2_3_3();
            }else if(valor == 9){
                cripto.decifra_2_3_3();
            }else if(valor == 10){
                cripto.cifra_2_3_3_ecb();
            }else if(valor == 11){
                cripto.decifra_2_3_3_ecb();
            }else if(valor == 12){
                cripto.cifra_2_3_3_ofb();
            }else if(valor == 13){
                cripto.decifra_2_3_3_ofb();
            }else if(valor == 14){
                cripto.cifra_2_3_3_cfb();
            }else if(valor == 15){
                cripto.decifra_2_3_3_cfb();
            }else if(valor == 16){
                cripto.c2_3_4();
            }else if(valor == 17){
                cripto.d2_3_4();
            }else if(valor == 18){
                cripto.g_c_assimetrica();
            }else if(valor == 19){
                cripto.cifrar_rsa();
            }else if(valor == 20){
                cripto.decifrar_rsa();
            }else if(valor == 21){
                cripto.cifra_hibrida();
            }else if(valor == 22){
                cripto.decifra_hibrida();
            }else if(valor == 23){
                cripto.cifrar_2x_sym();
            }else if(valor == 24){
                cripto.decifrar_2x_sym();
            }else if(valor == 25){
                cripto.sintese();
            }else if(valor == 26){
                cripto.sintese2();
            }else if(valor == 27){
                cripto.sintese2_5_2();
            }
            else {
                System.out.println("Por favor escolha um numero valido");
            }
            System.out.print("Opção: \t");
            valor = sc.nextInt();
        }
    }
}
