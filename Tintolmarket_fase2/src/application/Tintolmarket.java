package application;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import utils.Utils;

/**
 *
 * Classe principal do cliente Tintolmarket. Esta classe a responsavel por
 * estabelecer a conexao com o servidor, autenticar o utilizador e permitir a
 * interacao com o servidor atraves de comandos de texto.
 *
 */
public class Tintolmarket {

	private static SSLSocket socket;
	private static String name;

	public static void main(String[] args) {

		if (args.length != 5) {
			System.out.println(
					"A aplicacao deve ser iniciada da forma Tintolmarket <serverAddress> <truststore> <keystore> <password-keystore> <userID>");
			System.exit(0);
		}

		try {
			// retirar ip e port
			name = args[4];
			String[] serverInfo = args[0].split(":");
			String truststore = "stores//" + args[1];
			String keystore = "stores//" + name + "//" + args[2];
			String passwordKeystore = args[3];

			System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
			System.setProperty("javax.net.ssl.trustStore", truststore);
			System.setProperty("javax.net.ssl.trustStorePassword", "123456");

			FileInputStream truststorefile = new FileInputStream(truststore);
			KeyStore trustStore = KeyStore.getInstance("JCEKS");
			trustStore.load(truststorefile, "123456".toCharArray());

			FileInputStream keystorefile = new FileInputStream(keystore);
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(keystorefile, passwordKeystore.toCharArray());
			Certificate cert = keyStore.getCertificate(name + "_key"); // extrair o proprio certificado
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(name + "_key", passwordKeystore.toCharArray());

			// estabelecer ligacao
			if (serverInfo.length != 1)
				socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(serverInfo[0],
						Integer.parseInt(serverInfo[1]));
			else
				socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(serverInfo[0], 12345);

			// iniciar streams
			ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
			ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

			// efetuar login
			login(in, out, privateKey, cert);

			// interagir com o server
			interact(in, out, privateKey, trustStore); // alterar atribs

			// fechar ligacoes
			in.close();
			out.close();
			socket.close();
			keystorefile.close();
			truststorefile.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Efetua o login no servidor
	 * 
	 * @param in   ObjectInputStream para ler dados do servidor.
	 * @param out  ObjectOutputStream para enviar dados para o servidor.
	 * @param keys as chaves do user
	 * @param cert o certificado com a chave publica do user
	 * @throws Exception se ocorrer erro no processo
	 */
	private static void login(ObjectInputStream in, ObjectOutputStream out, PrivateKey key, Certificate cert)
			throws Exception {
		out.writeUTF(name);
		out.flush();

		byte[] nonce = (byte[]) in.readObject();

		byte[] signedNonce = Utils.signByteArray(key, nonce);

		if (in.readBoolean()) { // novo user
			out.writeObject(nonce);
			out.writeObject(signedNonce);
			out.writeObject(cert);
		} else { // user ja registado
			out.writeObject(signedNonce);
		}
		out.flush();

		if (in.readBoolean())
			System.out.println("Autenticacao bem sucedida!");
		else
			System.out.println("Erro na autenticacao!");
	}

	/**
	 * Metodo que permite ao utilizador interagir com o servidor atraves de comandos
	 * de texto. Os comandos sao lidos da entrada padrao e enviados ao servidor para
	 * serem processados. As respostas do servidor sao apresentadas na saida padrao.
	 *
	 * @param in         ObjectInputStream para ler dados do servidor.
	 * @param out        ObjectOutputStream para enviar dados para o servidor.
	 * @param trustStore a truststore partilhada
	 * @param keyStore   a keystore do cliente
	 * @throws Exception Se ocorrer algum erro durante a interacao com o servidor.
	 */
	private static void interact(ObjectInputStream in, ObjectOutputStream out, PrivateKey key, KeyStore trustStore)
			throws Exception {
		printCommands();
		Scanner sc = new Scanner(System.in);
		boolean exit = false;
		while (!exit) {
			System.out.print("\nInsira um comando: ");
			String line = sc.nextLine();
			String[] tokens = line.split(" ");
			boolean image = false;
			boolean wait = true;
			if (tokens[0].equals("a") || tokens[0].equals("add")) {
				wait = add(out, tokens);
			} else if (tokens[0].equals("s") || tokens[0].equals("sell")) {
				wait = sell(out, tokens, key);
			} else if (tokens[0].equals("v") || tokens[0].equals("view")) {
				wait = view(out, tokens);
				image = in.readBoolean();
			} else if (tokens[0].equals("b") || tokens[0].equals("buy")) {
				wait = buy(out, tokens, key);
			} else if (tokens[0].equals("w") || tokens[0].equals("wallet")) {
				wait = wallet(out, tokens);
			} else if (tokens[0].equals("c") || tokens[0].equals("classify")) {
				wait = classify(out, tokens);
			} else if (tokens[0].equals("t") || tokens[0].equals("talk")) {
				wait = talk(out, trustStore, tokens);
			} else if (tokens[0].equals("r") || tokens[0].equals("read")) {
				wait = read(out, in, key, tokens);
			} else if (tokens[0].equals("l") || tokens[0].equals("list")) {
				wait = list(out, tokens);
			} else if (tokens[0].equals("exit")) {
				System.out.println("Programa encerrado.");
				out.writeUTF("exit");
				exit = true;
				wait = false;
			} else {
				System.out.println("Comando nao reconhecido");
				printCommands();
				wait = false;
			}
			out.flush();

			if (wait)
				System.out.println(in.readUTF());
			if (image)
				getImage(in);
		}
		sc.close();
	}

	private static void printCommands() {
		System.out.println(
				"Comandos disponiveis: \n\tadd <wine> <image> - adiciona um novo vinho identificado por wine, associado a imagem\r\n"
						+ "image.\n"
						+ "\tsell <wine> <value> <quantity> - coloca a venda o numero indicado por quantity de\r\n"
						+ "unidades do vinho wine pelo valor value.\n"
						+ "\tview <wine> - obtem as informacoes associadas ao vinho identificado por wine,\r\n"
						+ "nomeadamente a imagem associada, a classificacao media e, caso existam unidades do\r\n"
						+ "vinho disponiveis para venda, a indicacao do utilizador que as disponibiliza, o preco e a\r\n"
						+ "quantidade disponivel.\n"
						+ "\tbuy <wine> <seller> <quantity> - compra quantity unidades do vinho wine ao utilizador\r\n"
						+ "seller.\n" + "\twallet - obtem o saldo atual da carteira.\r\n"
						+ "\tclassify <wine> <stars> - atribui ao vinho wine uma classificacao de 1 a 5.\r\n"
						+ "\ttalk <user> <message> - permite enviar uma mensagem privada ao utilizador user.\n"
						+ "\tread - permite ler as novas mensagens recebidas.");
	}

	private static boolean add(ObjectOutputStream out, String[] tokens) throws Exception {
		boolean wait = true;
		if (tokens.length != 3) {
			System.out.println("O comando add e usado na forma \"add <wine> <image>\"");
			wait = false;
		} else {
			File img = new File(tokens[2]);
			if (img.exists()) {
				out.writeUTF("a");
				out.writeUTF(tokens[1]);
				out.writeUTF(img.getName());
				byte[] bytes = Files.readAllBytes(img.toPath());
				out.writeObject(bytes);
			} else {
				System.out.println("A imagem " + tokens[2] + " nao existe!");
				wait = false;
			}
		}
		return wait;
	}

	private static boolean sell(ObjectOutputStream out, String[] tokens, PrivateKey privateKey) throws Exception {
		boolean wait = true;
		if (tokens.length != 4) {
			System.out.println("O comando sell e usado na forma \"sell <wine> <value> <quantity>\"");
			wait = false;
		} else {

			String wine = tokens[1];
			int qty = Integer.parseInt(tokens[3]);
			double value = Double.parseDouble(tokens[2]);
			String s = String.format("%s%d%.2f", wine, qty, value);
			byte[] signed = Utils.signString(privateKey, s);

			out.writeUTF("s");
			out.writeUTF(wine);
			out.writeDouble(value);
			out.writeInt(qty);
			out.writeObject(signed);
		}
		return wait;
	}

	private static boolean view(ObjectOutputStream out, String[] tokens) throws Exception {
		boolean wait = true;
		if (tokens.length != 2) {
			System.out.println("O comando view e usado na forma \"view <wine>\"");
			wait = false;
		} else {
			out.writeUTF("v");
			out.writeUTF(tokens[1]);
			out.flush();
		}
		return wait;
	}

	private static boolean buy(ObjectOutputStream out, String[] tokens, PrivateKey privateKey) throws Exception {
		boolean wait = true;
		if (tokens.length != 4) {
			System.out.println("O comando buy e usado na forma \"buy <wine> <seller> <quantity>\"");
			wait = false;
		} else {

			String wine = tokens[1];
			int qty = Integer.parseInt(tokens[3]);
			String seller = tokens[2];
			String s = String.format("%s%d%s", wine, qty, seller);
			byte[] signed = Utils.signString(privateKey, s);

			out.writeUTF("b");
			out.writeUTF(wine);
			out.writeUTF(seller);
			out.writeInt(qty);
			out.writeObject(signed);
		}
		return wait;
	}

	private static boolean wallet(ObjectOutputStream out, String[] tokens) throws Exception {
		boolean wait = true;
		if (tokens.length != 1) {
			System.out.println("O comando wallet e usado na forma \"wallet\"");
			wait = false;
		} else {
			out.writeUTF("w");
		}
		return wait;
	}

	private static boolean classify(ObjectOutputStream out, String[] tokens) throws Exception {
		boolean wait = true;
		if (tokens.length != 3) {
			System.out.println("O comando classify e usado na forma \"classify <wine> <stars>\"");
			wait = false;
		} else {
			out.writeUTF("c");
			out.writeUTF(tokens[1]);
			out.writeUTF(tokens[2]);
		}
		return wait;
	}

	private static boolean talk(ObjectOutputStream out, KeyStore trustStore, String[] tokens) throws Exception {
		boolean wait = true;
		if (tokens.length < 3) {
			System.out.println("O comando talk e usado na forma \"talk <user> <message>\"");
			wait = false;
		} else {
			StringBuilder sb = new StringBuilder();
			for (int i = 2; i < tokens.length; i++)
				sb.append(tokens[i] + " ");
			Certificate dest = trustStore.getCertificate("newcert_" + tokens[1]);
			String cypheredMessage = Utils.cipher(Cipher.ENCRYPT_MODE, dest.getPublicKey(), sb.toString());
			out.writeUTF("t");
			out.writeUTF(tokens[1]);
			out.writeUTF(cypheredMessage);
		}
		return wait;
	}

	private static boolean read(ObjectOutputStream out, ObjectInputStream in, PrivateKey key, String[] tokens)
			throws Exception {
		if (tokens.length != 1) {
			System.out.println("O comando read e usado na forma \"read \"");
		} else {
			out.writeUTF("r");
			out.flush();
			String recieved = in.readUTF();
			String[] users = recieved.split("(?!\\[.*), (?![^\\[]*?\\])");
			for (String s : users) {
				s = s.substring(s.indexOf("[") + 1, s.length() - 3);
				String[] msgs = s.split(", ");
				for (String msg : msgs)
					recieved = recieved.replace(msg, Utils.cipher(Cipher.DECRYPT_MODE, key, msg));
			}
			System.out.println(recieved);
		}
		return false;
	}

	private static boolean list(ObjectOutputStream out, String[] tokens) throws Exception {
		boolean wait = true;
		if (tokens.length != 1) {
			System.out.println("O comando list e usado na forma \"list\"");
			wait = false;
		} else {
			out.writeUTF("l");
		}
		return wait;
	}

	private static void getImage(ObjectInputStream in) throws Exception {
		File dir = new File(name);
		if (!dir.exists())
			dir.mkdir();
		File img = new File(name + "//" + in.readUTF());
		img.createNewFile();
		FileOutputStream file = new FileOutputStream(img);
		byte[] bytes = (byte[]) in.readObject();
		file.write(bytes, 0, bytes.length);
		file.close();
	}

}
