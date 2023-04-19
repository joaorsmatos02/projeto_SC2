package application;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Scanner;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

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
			PublicKey publicKey = cert.getPublicKey();
			KeyPair userKeys = new KeyPair(publicKey, privateKey);

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
			login(in, out, userKeys, cert);

			// interagir com o server
			interact(in, out, keyStore, trustStore); // alterar atribs

			// fechar ligacoes
			in.close();
			out.close();
			socket.close();

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
	private static void login(ObjectInputStream in, ObjectOutputStream out, KeyPair keys, Certificate cert)
			throws Exception {
		out.writeUTF(name);
		out.flush();

		byte[] nonce = new byte[8];
		for (int i = 0; i < 8; i++)
			nonce[i] = in.readByte();

		byte[] signedNonce = sign(nonce, keys.getPrivate());

		if (in.readBoolean()) { // novo user
			out.write(nonce);
			out.write(signedNonce);
			out.writeObject(cert);
		} else { // user ja registado
			out.write(signedNonce);
		}
		out.flush();

		if (in.readBoolean())
			System.out.println("Autenticacao bem sucedida!");
		else
			System.out.println("Erro na autenticacao!");
	}

	/**
	 * Assina o nonce com a chave privada fornecida
	 * 
	 * @param nonce o nonce a assinar
	 * @param pk    a chave a usar na assinatura
	 * @return um byte[] com o nonce assinado
	 * @throws Exception se ocorrer algum erro durante a assinatura
	 */
	private static byte[] sign(byte[] nonce, PrivateKey pk) throws Exception {
		Signature s = Signature.getInstance("SHA256withRSA");
		s.initSign(pk);
		s.update(nonce);
		return s.sign();
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
	private static void interact(ObjectInputStream in, ObjectOutputStream out, KeyStore keyStore, KeyStore trustStore)
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
				wait = sell(out, tokens);
			} else if (tokens[0].equals("v") || tokens[0].equals("view")) {
				wait = view(out, tokens);
				out.flush();
				image = in.readBoolean();
			} else if (tokens[0].equals("b") || tokens[0].equals("buy")) {
				wait = buy(out, tokens);
			} else if (tokens[0].equals("w") || tokens[0].equals("wallet")) {
				wait = wallet(out, tokens);
			} else if (tokens[0].equals("c") || tokens[0].equals("classify")) {
				wait = classify(out, tokens);
			} else if (tokens[0].equals("t") || tokens[0].equals("talk")) {
				wait = talk(out, tokens);
			} else if (tokens[0].equals("r") || tokens[0].equals("read")) {
				wait = read(out, tokens);
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
				FileInputStream file = new FileInputStream(img);
				out.writeLong(file.getChannel().size()); // enviar tamanho
				out.writeUTF(img.getName()); // enviar nome
				byte[] bytes = new byte[16 * 1024];
				while (file.read(bytes) > 0)
					out.write(bytes);
				file.close();
			} else {
				System.out.println("A imagem " + tokens[2] + " nao existe!");
				wait = false;
			}
		}
		return wait;
	}

	private static boolean sell(ObjectOutputStream out, String[] tokens) throws Exception {
		boolean wait = true;
		if (tokens.length != 4) {
			System.out.println("O comando sell e usado na forma \"sell <wine> <value> <quantity>\"");
			wait = false;
		} else { //////////////////////////////////////////////////////////////////////
			// TODO//////////////// enviar informacao assinada (4.3) /////////////////
			/////////////////////////////////////////////////////////////////////////
			out.writeUTF("s");
			out.writeUTF(tokens[1]);
			out.writeUTF(tokens[2]);
			out.writeUTF(tokens[3]);
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
		}
		return wait;
	}

	private static boolean buy(ObjectOutputStream out, String[] tokens) throws Exception {
		boolean wait = true;
		if (tokens.length != 4) {
			System.out.println("O comando buy e usado na forma \"buy <wine> <seller> <quantity>\"");
			wait = false;
		} else { //////////////////////////////////////////////////////////////////////
			// TODO////////////////// enviar informacao assinada (4.3) ///////////////
			/////////////////////////////////////////////////////////////////////////
			out.writeUTF("b");
			out.writeUTF(tokens[1]);
			out.writeUTF(tokens[2]);
			out.writeUTF(tokens[3]);
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

	private static boolean talk(ObjectOutputStream out, String[] tokens) throws Exception {
		boolean wait = true;
		/////////////////////////////////////////////////////////////////////////////////////
		// TODO ir buscar certificado e extrair chave publica do destinatario a
		///////////////////////////////////////////////////////////////////////////////////// truststore
		/////////////////////////////////////////////////////////////////////////////////////
		if (tokens.length < 3) {
			System.out.println("O comando talk e usado na forma \"talk <user> <message>\"");
			wait = false;
		} else {
			StringBuilder sb = new StringBuilder();
			for (int i = 2; i < tokens.length; i++) {
				sb.append(tokens[i] + " ");
			}
			///////////////////////////////////////////////////////////////////////
			// TODO falta cifrar a mensagem com a key publica do user tokens[1] //
			/////////////////////////////////////////////////////////////////////
			String message = sb.toString();
			String cypheredMessage = message;
			out.writeUTF("t");
			out.writeUTF(tokens[1]);
			out.writeUTF(cypheredMessage);
		}
		return wait;
	}

	private static boolean read(ObjectOutputStream out, String[] tokens) throws Exception {
		boolean wait = true;
		/////////////////////////////////////////////////////////////
		// TODO ir buscar chave privada do destinatario a keystore //
		/////////////////////////////////////////////////////////////
		if (tokens.length != 1) {
			System.out.println("O comando read e usado na forma \"read \"");
			wait = false;
		} else {
			out.writeUTF("r");
		}
		return wait;
	}

	private static void getImage(ObjectInputStream in) throws Exception {
		long fileSize = in.readLong(); // ler tamanho da imagem
		int bytesRead;
		long totalBytesRead = 0;
		File dir = new File(name);
		if (!dir.exists())
			dir.mkdir();
		File img = new File(name + "//" + in.readUTF());
		img.createNewFile();
		FileOutputStream file = new FileOutputStream(img);
		byte[] bytes = new byte[16 * 1024];
		while (totalBytesRead < fileSize) {
			bytesRead = in.read(bytes);
			file.write(bytes, 0, bytesRead);
			totalBytesRead += bytesRead;
		}
		file.close();
		while (in.available() > 0) // limpar stream depois de transferir ficheiro
			in.read(bytes);
	}
}
