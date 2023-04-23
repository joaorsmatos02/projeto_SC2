package utils;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;

import javax.crypto.Cipher;

/**
 * Classe Utils que fornece metodos uteis para manipular arquivos e outros
 * auxiliares.
 */
public class Utils {

	/**
	 * Substitui uma linha especifica em um arquivo por outra. Se a nova linha for
	 * nula, a linha antiga sera removida.
	 * 
	 * @param file    O arquivo onde a linha sera substituida.
	 * @param oldLine A linha antiga que sera substituida ou removida.
	 * @param newLine A nova linha que substituira a antiga. Se for null, a linha
	 *                antiga sera removida.
	 */
	public static synchronized void replaceLine(File file, String oldLine, String newLine) {
		try {
			File newFile = new File("temp.txt");
			newFile.createNewFile();
			FileWriter fw = new FileWriter(newFile, true);
			Scanner sc = new Scanner(file);
			while (sc.hasNextLine()) {
				String next = sc.nextLine();
				if (next.equals(oldLine)) {
					if (newLine != null)
						fw.append(newLine + "\n");
				} else
					fw.append(next + "\n");
			}
			fw.close();
			sc.close();
			file.delete();
			newFile.renameTo(file);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Assina o nonce com a chave privada fornecida
	 *
	 * @param pk    a chave a usar na assinatura
	 * @param nonce o nonce a assinar
	 * @return um byte[] com o nonce assinado
	 */
	public static byte[] signString(PrivateKey privateKey, String nonce) {
		return signByteArray(privateKey, nonce.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Assina o nonce com a chave privada fornecida
	 *
	 * @param pk    a chave a usar na assinatura
	 * @param nonce o nonce a assinar
	 * @return um byte[] com o nonce assinado
	 */
	public static byte[] signByteArray(PrivateKey pk, byte[] nonce) {
		try {
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initSign(pk);
			s.update(nonce);
			return s.sign();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static boolean verifySignature(PublicKey publicKey, byte[] nonce, byte[] encryptedNonce) {
		try {
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(publicKey);
			signature.update(nonce);
			return signature.verify(encryptedNonce);
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		return false;
	}

	public static byte[] cipherAsymmetric(int mode, Key key, byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		if (mode == Cipher.DECRYPT_MODE)
			cipher.init(Cipher.DECRYPT_MODE, (PrivateKey) key);
		else
			cipher.init(Cipher.ENCRYPT_MODE, (PublicKey) key);
		return cipher.doFinal(data);
	}

}
