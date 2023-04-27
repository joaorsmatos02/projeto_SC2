package utils;

import java.io.File;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import application.TintolmarketServer;
import exceptions.InvalidHashException;

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
			SecretKey sk = TintolmarketServer.getFileKey();
			File newFile = new File("temp.txt");
			newFile.createNewFile();
			FileWriter fw = new FileWriter(newFile, true);
			Scanner sc = new Scanner(file);
			while (sc.hasNextLine()) {
				String next = cipherSymmetricString(Cipher.DECRYPT_MODE, sk, sc.nextLine());
				if (next.equals(oldLine)) {
					if (newLine != null)
						fw.append(cipherSymmetricString(Cipher.ENCRYPT_MODE, sk, newLine) + "\r\n");
				} else
					fw.append(cipherSymmetricString(Cipher.ENCRYPT_MODE, sk, next) + "\r\n");
			}
			fw.close();
			sc.close();
			file.delete();
			newFile.renameTo(file);
			updateHash(new File(file.getAbsolutePath()));
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

	/**
	 * Verifica uma assinatura
	 * 
	 * @param publicKey      a chave publica a usar
	 * @param nonce          o nonce original
	 * @param encryptedNonce o nonce encriptado
	 * @return true se a assinatura e valida, false caso contrario
	 */
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

	/**
	 * Cifra ou decifra assimetricamente uma string
	 * 
	 * @param mode indica se sera feita uma cifra (Cipher.ENCRYPT_MODE) ou decifra
	 *             (Cipher.DECRYPT_MODE)
	 * @param key  a chave a usar
	 * @param data os dados a cifrar
	 * @return a string cifrada/decifrada
	 * @throws Exception
	 */
	public static String cipherAssimetricString(int mode, Key key, String data) throws Exception {
		if (mode == Cipher.DECRYPT_MODE) {
			byte[] bytes = Base64.getDecoder().decode(data.getBytes(StandardCharsets.UTF_8));
			bytes = cipherAsymmetric(mode, key, bytes);
			return new String(bytes, StandardCharsets.UTF_8);
		} else {
			byte[] bytes = cipherAsymmetric(mode, key, data.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(bytes);
		}
	}

	/**
	 * Cifra ou decifra assimetricamente um array de bytes
	 * 
	 * @param mode indica se sera feita uma cifra (Cipher.ENCRYPT_MODE) ou decifra
	 *             (Cipher.DECRYPT_MODE)
	 * @param key  a chave a usar
	 * @param data os dados a cifrar
	 * @return os bytes cifrados/decifrados
	 * @throws Exception
	 */
	public static byte[] cipherAsymmetric(int mode, Key key, byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		if (mode == Cipher.DECRYPT_MODE)
			cipher.init(Cipher.DECRYPT_MODE, (PrivateKey) key);
		else
			cipher.init(Cipher.ENCRYPT_MODE, (PublicKey) key);
		return cipher.doFinal(data);
	}

	/**
	 * Cifra ou decifra simetricamente uma string
	 * 
	 * @param mode indica se sera feita uma cifra (Cipher.ENCRYPT_MODE) ou decifra
	 *             (Cipher.DECRYPT_MODE)
	 * @param key  a chave a usar
	 * @param data os dados a cifrar
	 * @return a string cifrada/decifrada
	 * @throws Exception
	 */
	public static String cipherSymmetricString(int mode, SecretKey key, String data) throws Exception {
		if (mode == Cipher.DECRYPT_MODE) {
			byte[] bytes = Base64.getDecoder().decode(data.getBytes(StandardCharsets.UTF_8));
			bytes = cipherSymmetric(mode, key, bytes);
			return new String(bytes, StandardCharsets.UTF_8);
		} else {
			byte[] bytes = cipherSymmetric(mode, key, data.getBytes(StandardCharsets.UTF_8));
			return Base64.getEncoder().encodeToString(bytes);
		}
	}

	/**
	 * Cifra ou decifra simetricamente um array de bytes
	 * 
	 * @param mode indica se sera feita uma cifra (Cipher.ENCRYPT_MODE) ou decifra
	 *             (Cipher.DECRYPT_MODE)
	 * @param key  a chave a usar
	 * @param data os dados a cifrar
	 * @return os bytes cifrados/decifrados
	 * @throws Exception
	 */
	public static byte[] cipherSymmetric(int mode, SecretKey key, byte[] data) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(mode, key);
		return cipher.doFinal(data);
	}

	/**
	 * Atualiza o hash do file fornecido
	 * 
	 * @param file o ficheiro a atualizar
	 * @throws InvalidHashException
	 */
	public static void updateHash(File file) throws InvalidHashException {
		try {
			File macs = new File("txtFiles//HMAC.txt");
			if (!macs.exists()) {
				macs.createNewFile();
				if (file.exists())
					throw new InvalidHashException("Ficheiro HMACS nao encontrado");
			} else {
				SecretKey key = TintolmarketServer.getFileKey();
				File newMacs = new File("txtFiles//temp.txt");
				newMacs.createNewFile();
				FileWriter fw = new FileWriter(newMacs, true);
				Scanner sc = new Scanner(macs);
				boolean found = false;
				String newLine = Utils.cipherSymmetricString(Cipher.ENCRYPT_MODE, key,
						file.getName() + ":" + calculateHmac(file)) + "\r\n";
				while (sc.hasNextLine()) {
					String encryptedLine = sc.nextLine();
					String decryptedLine = Utils.cipherSymmetricString(Cipher.DECRYPT_MODE, key, encryptedLine);
					if (decryptedLine.startsWith(file.getName())) {
						fw.append(newLine);
						found = true;
					} else {
						fw.append(encryptedLine + "\r\n");
					}
				}
				if (!found)
					fw.append(newLine);
				fw.close();
				sc.close();
				macs.delete();
				newMacs.renameTo(macs);
			}
		} catch (InvalidHashException e) {
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * Verifica a integridade do ficheiro fornecido atraves do seu hash
	 * 
	 * @param file o ficheiro a verificar
	 * @throws InvalidHashException
	 */
	public static void verifyIntegrity(File file) throws Exception {
		Scanner sc = null;
		File txtFolder = new File("txtFiles");
		File macs = new File("txtFiles//HMAC.txt");
		try {
			if (!txtFolder.exists())
				txtFolder.mkdir();
			if (!macs.exists()) {
				macs.createNewFile();
				if (file.exists())
					throw new InvalidHashException("Ficheiro HMACS nao encontrado");
			} else {
				if (!file.exists())
					return;
				SecretKey key = TintolmarketServer.getFileKey();
				sc = new Scanner(macs);
				boolean found = false;
				while (sc.hasNextLine()) {
					String line = Utils.cipherSymmetricString(Cipher.DECRYPT_MODE, key, sc.nextLine());
					if (line.startsWith(file.getName())) {
						found = true;
						String hmac = line.split(":")[1];
						if (!hmac.equals(calculateHmac(file))) {
							sc.close();
							throw new InvalidHashException("HMAC invalido");
						}
					}
					if (!sc.hasNextLine() && !found) {
						sc.close();
						throw new InvalidHashException("HMAC nao encontrado");
					}
				}
				sc.close();
			}
		} catch (Exception e) {
			throw e;
		}
	}

	/**
	 * Calcula o hmac do ficheiro fornecido
	 * 
	 * @param file o ficheiro a usar
	 * @return uma string com o hash de file
	 */
	private static String calculateHmac(File file) {
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(TintolmarketServer.getFileKey());
			mac.update(Files.readAllBytes(file.toPath()));
			byte[] hmac = mac.doFinal();
			return Base64.getEncoder().encodeToString(hmac);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
