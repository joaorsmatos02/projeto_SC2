package catalogs;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import entities.User;
import exceptions.WrongCredentialsException;

/**
 * A classe UserCatalog e responsavel por gerir o catalogo de utilizadores. Esta
 * classe permite criar um novo utilizador, adicionar um utilizador e fazer
 * login de um utilizador.
 */
public class UserCatalog {

	private static UserCatalog instance;
	private List<User> users;

	/**
	 * Construtor privado da classe UserCatalog.
	 */
	private UserCatalog() {
		users = new ArrayList<>();
		File txtFolder = new File("txtFiles");
		File userInfo = new File("txtFiles//userCatalog.txt");
		try {
			if (!txtFolder.exists())
				txtFolder.mkdir();
			if (!userInfo.exists())
				userInfo.createNewFile();
			else
				getUsersByTextFile(userInfo);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Retorna uma instancia do catalogo de utilizadores.
	 * 
	 * @return uma instancia do catalogo de utilizadores.
	 */
	public static UserCatalog getInstance() {
		if (instance == null) {
			instance = new UserCatalog();
		}
		return instance;
	}

	/**
	 * Efetua o login do utilizador ou cria um novo utilizador.
	 * 
	 * @param in       ObjectInputStream para ler dados do servidor.
	 * @param out      ObjectOutputStream para enviar dados para o servidor.
	 * @param keyStore a keystore do server
	 * @return o nome de utilizador se o login for bem-sucedido, ou null caso
	 *         contrario.
	 * @throws IOException               Se ocorrer um erro ao ler ou escrever.
	 * @throws ClassNotFoundException    Se a classe nao for encontrada.
	 * @throws WrongCredentialsException Se as credenciais estiverem incorretas.
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws SignatureException
	 */
	public synchronized String login(ObjectInputStream in, ObjectOutputStream out, KeyStore keyStore)
			throws ClassNotFoundException, IOException, WrongCredentialsException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, SignatureException {

		// TODO SECCAO 4.2 do projeto
		// da primeira vez que um cliente se liga envia o seu certificado com a sua
		// chave publica
		// o server guarda esse certificado na sua keystore
		// quando se for autenticar a partir dai o server cria o nonce, cifra com a
		// chave publica do cliente e envia para ele
		// o cliente deve decifrar com a sua chave privada e enviar de volta para
		// mostrar que tem a chave privada correspondente
		/////////////////////////////////////////////////////////////////////////////

		File users = new File("txtFiles//userCreds.txt");
		users.createNewFile();
		Scanner sc = new Scanner(users);
		Cipher encryptCipher = Cipher.getInstance("RSA");
		Cipher decryptCipher = Cipher.getInstance("RSA");

		// le user e verifica se ja existe
		String user = in.readUTF();
		boolean newUser = true;
		String line;
		while (sc.hasNextLine()) {
			line = sc.nextLine();
			if (line.startsWith(user)) {
				newUser = false;
				break;
			}
		}
		sc.close();

		SecureRandom rd = new SecureRandom();
		byte[] nonce = new byte[8];
		rd.nextBytes(nonce);

		boolean result = true;
		if (newUser) { // se o user nao existir faz o seu registo
			out.write(nonce);
			out.writeBoolean(newUser);

			for (int i = 0; i < 8 && result; i++) // verificar se o nonce e igual ao enviado
				result = in.readByte() == nonce[i];

			byte[] encryptedNonce = new byte[8]; // receber assinatura e certificado
			for (int i = 0; i < 8 && result; i++)
				encryptedNonce[i] = in.readByte();
			Certificate cert = (Certificate) in.readObject();

			// verificar assinatura e certificado
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(cert.getPublicKey());
			signature.update(encryptedNonce);
			result = signature.verify(encryptedNonce); // ??????

			if (result) {
				this.addUser(user);
				FileWriter fw = new FileWriter("txtFiles//userCreds.txt", true);
				fw.write(user + ":" + "ficheiro do certificado??" + "\n");
				fw.close();
			}

		} else {
			// ir buscar certificado do user e cifrar nonce com a sua chave publica
			Certificate cert = keyStore.getCertificate(user + "_key");
			encryptCipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
			byte[] encryptedNonce = encryptCipher.doFinal(nonce);

			out.write(encryptedNonce);
			out.writeBoolean(newUser);

			for (int i = 0; i < 8 && result; i++) // verificar nonce recebido
				result = in.readByte() == nonce[i];
		}

		if (result)
			out.writeBoolean(true);
		else {
			out.writeBoolean(false);
			user = null;
		}

		return user;
	}

	/**
	 * Le e armazena os utilizadores do ficheiro de texto userInfo.
	 * 
	 * @param userInfo O arquivo de texto com as informacoes dos utilizadores.
	 */
	private void getUsersByTextFile(File userInfo) {
		try {
			Scanner sc = new Scanner(userInfo);
			while (sc.hasNextLine()) {
				String[] line = sc.nextLine().split("(?!\\{.*)\\s(?![^{]*?\\})");
				users.add(new User(line[0], Double.parseDouble(line[1]), stringToHashMap(line[2])));
			}
			sc.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Retorna um objeto User com base no nome do utilizador.
	 * 
	 * @param userName O nome do utilizador.
	 * @return Um objeto User correspondente ao nome do utilizador.
	 */
	public User getUserByName(String userName) {
		for (User u : this.users)
			if (u.getName().equals(userName))
				return u;
		return null;
	}

	/**
	 * Adiciona um novo utilizador a lista de utilizadores e ao arquivo de texto.
	 * 
	 * @param userName O nome do novo utilizador.
	 */
	public synchronized void addUser(String userName) {
		try {
			User u = new User(userName, 200, new HashMap<>());
			this.users.add(u);
			File userInfo = new File("txtFiles//userCatalog.txt");
			FileWriter fw = new FileWriter(userInfo, true);
			fw.write(u.toString() + "\r\n");
			fw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Converte uma string em um HashMap de strings e listas de strings.
	 * 
	 * @param line A string a ser convertida.
	 * @return Um HashMap com strings como chaves e listas de strings como valores.
	 */
	public HashMap<String, List<String>> stringToHashMap(String line) {
		HashMap<String, List<String>> result = new HashMap<>();
		line = line.substring(1, line.length() - 1);
		String[] hashContents = line.split("(?!\\[.*), (?![^\\[]*?\\])");
		if (hashContents[0].contains("=")) {
			for (String s : hashContents) {
				String[] item = s.split("=");
				item[1] = item[1].substring(1, item[1].length() - 1);
				List<String> value = Arrays.asList(item[1].split(", "));
				result.put(item[0], value);
			}
		}
		return result;
	}

}
