package application;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import catalogs.BlockChain;
import catalogs.UserCatalog;
import catalogs.WineAdCatalog;
import catalogs.WineCatalog;
import entities.User;
import exceptions.BlockChainException;
import exceptions.WineNotFoundException;
import exceptions.WrongCredentialsException;
import handlers.AddInfoHandler;
import handlers.ShowInfoHandler;
import handlers.TransactionHandler;
import utils.Utils;

/**
 * Classe principal do servidor Tintolmarket.
 */
public class TintolmarketServer {

	private static SecretKey fileKey;
	private static KeyStore keyStore;

	public static void main(String[] args) {

		SSLServerSocket serverSocket = null;

		String filePassword = null;
		String keyStorePath = null;
		String passwordKeystore = null;

		// criar socket
		try {
			System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
			if (args.length == 4) {
				keyStorePath = "stores//server//" + args[2];
				passwordKeystore = args[3];
				System.setProperty("javax.net.ssl.keyStore", keyStorePath);
				System.setProperty("javax.net.ssl.keyStorePassword", passwordKeystore);
				serverSocket = (SSLServerSocket) SSLServerSocketFactory.getDefault()
						.createServerSocket(Integer.parseInt(args[0]));
				filePassword = args[1];
			} else if (args.length == 3) {
				keyStorePath = "stores//" + args[1];
				passwordKeystore = args[2];
				System.setProperty("javax.net.ssl.keyStore", keyStorePath);
				System.setProperty("javax.net.ssl.keyStorePassword", passwordKeystore);
				serverSocket = (SSLServerSocket) SSLServerSocketFactory.getDefault().createServerSocket(12345);
				filePassword = args[0];
			} else {
				System.out.println(
						"Argumentos invalidos. O servidor e iniciado na forma TintolmarketServer <port> <password-cifra> <keystore> <password-keystore>.");
			}
		} catch (IOException e1) {
			e1.printStackTrace();
			System.out.println("Erro na conexao com cliente");
		}

		try {

			File file = new File(keyStorePath);
			FileInputStream is = new FileInputStream(file);
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(is, passwordKeystore.toCharArray());

			byte[] salt = { (byte) 0xc9, (byte) 0x36, (byte) 0x78, (byte) 0x99, (byte) 0x52, (byte) 0x3e, (byte) 0xea,
					(byte) 0xf2 };
			PBEKeySpec keySpec = new PBEKeySpec(filePassword.toCharArray(), salt, 20);
			SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
			fileKey = kf.generateSecret(keySpec);

			try {
				Utils.verifyIntegrity(new File("txtFiles//userCreds.txt"));
				Utils.verifyIntegrity(new File("txtFiles//userCatalog.txt"));
				Utils.verifyIntegrity(new File("txtFiles//wineCatalog.txt"));
				Utils.verifyIntegrity(new File("txtFiles//wineAdsCatalog.txt"));
			} catch (Exception e) {
				System.out.println("Erro ao verificar a integridade dos ficheiros.");
				System.exit(0);
			}

			BlockChain blockChain = null;
			try {
				blockChain = BlockChain.getInstance();
				blockChain.setKey(null, null);
				Certificate serverCert = keyStore.getCertificate("server_key");
				PrivateKey pvk = (PrivateKey) keyStore.getKey("server_key", passwordKeystore.toCharArray());
				blockChain.setKey(serverCert.getPublicKey(), pvk);
				blockChain.verifyIntegrity();
			} catch (BlockChainException e) {
				System.out.println("Erro ao verificar a integridade da blockchain.");
				System.exit(0);
			}

			UserCatalog.getInstance();
			WineCatalog.getInstance();
			WineAdCatalog.getInstance();

			while (true) {
				SSLSocket socket = (SSLSocket) serverSocket.accept();
				ServerThread st = new ServerThread(socket, blockChain);
				st.start();
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
		}

		try {
			serverSocket.close();
		} catch (IOException e) {
			System.out.println("Erro ao fechar socket.");
		}
	}

	/**
	 * Obtem a chave usada para cifrar os ficheiros txt
	 * 
	 * @return a chave usada para cifrar os ficheiros txt
	 */
	public static SecretKey getFileKey() {
		return fileKey;
	}

	/**
	 * Obtem a KeyStore do server
	 * 
	 * @return a KeyStore do server
	 */
	public static KeyStore getKeyStore() {
		return keyStore;
	}

}

/**
 * 
 * Classe ServerThread que representa uma thread para comunicacao com os
 * clientes.
 */
class ServerThread extends Thread {

	private SSLSocket socket;
	private BlockChain blockChain;

	public ServerThread(SSLSocket inSoc, BlockChain blockChain) {
		this.socket = inSoc;
		this.blockChain = blockChain;
	}

	@Override
	public void run() {

		System.out.println("Cliente conectado");
		ObjectOutputStream out = null;
		ObjectInputStream in = null;

		try {
			// iniciar streams
			out = new ObjectOutputStream(socket.getOutputStream());
			in = new ObjectInputStream(socket.getInputStream());

			// fazer login do user
			UserCatalog userCatalog = UserCatalog.getInstance();
			String name = userCatalog.login(in, out);
			if (name != null) {
				out.writeBoolean(true);
				out.flush();
				interact(userCatalog.getUserByName(name), socket, in, out);
				System.out.println("Cliente desconectado");
			}

		} catch (WrongCredentialsException e) {
			try {
				System.out.println(e.getMessage());
				out.writeBoolean(false);
				out.flush();
			} catch (IOException e1) {
				System.out.println("Ocorreu um erro na comunicacao");
			}
		} catch (Exception e) {
			System.out.println("Cliente desconectado");
		} finally {
			try {
				// fechar ligacoes
				in.close();
				out.close();
				socket.close();
			} catch (IOException e) {
				System.out.println("Ocorreu um erro na comunicacao");
			}
		}
	}

	/**
	 * Metodo para interagir com o usuario apos a autenticacao bem sucedida.
	 * 
	 * @param user instancia do usuario logado
	 * @param in   ObjectInputStream para receber informacoes do cliente
	 * @param out  ObjectOutputStream para enviar informacoes ao cliente
	 * @throws Exception em caso de erro na comunicacao com o cliente
	 */
	private void interact(User user, SSLSocket socket, ObjectInputStream in, ObjectOutputStream out) throws Exception {
		boolean exit = false;
		while (!exit) {
			boolean image = false;
			try {
				String command = in.readUTF();
				switch (command) {
				case "a":
					add(in, out);
					break;
				case "s":
					sell(in, out, user);
					break;
				case "v":
					image = true;
					view(in, out);
					break;
				case "b":
					buy(in, out, user);
					break;
				case "w":
					wallet(out, user);
					break;
				case "c":
					classify(in, out, user);
					break;
				case "t":
					talk(in, out, user);
					break;
				case "r":
					read(out, user);
					break;
				case "l":
					list(out);
					break;
				default:
					exit = true;
					break;
				}
				out.flush();
				image = false;
			} catch (WineNotFoundException e) {
				if (image)
					out.writeBoolean(false);
				out.writeUTF(e.getMessage());
				out.flush();
			} catch (Exception e) {
				out.writeUTF(e.getMessage());
				out.flush();
			}
		}
	}

	/**
	 * Representa a funcao add
	 * 
	 * @param in  a stream de input
	 * @param out a stream de output
	 * @throws Exception
	 */
	private static void add(ObjectInputStream in, ObjectOutputStream out) throws Exception {
		String arg1 = in.readUTF();
		File imgFiles = new File("imgFiles");
		if (!imgFiles.exists())
			imgFiles.mkdir();
		File image = new File("imgFiles//" + in.readUTF()); // ler nome da imagem
		FileOutputStream file = new FileOutputStream(image);
		byte[] bytes = (byte[]) in.readObject();
		file.write(bytes, 0, bytes.length);
		file.close();
		AddInfoHandler.add(arg1, image);
		out.writeUTF(String.format("Vinho %s adicionado com sucesso!", arg1));
	}

	/**
	 * Representa a funcao sell
	 * 
	 * @param in   a stream de input
	 * @param out  a stream de output
	 * @param user o utilizador em questao
	 * @throws Exception
	 */
	private static void sell(ObjectInputStream in, ObjectOutputStream out, User user) throws Exception {
		String wine = in.readUTF();
		double price = in.readDouble();
		int qty = in.readInt();
		byte[] signature = (byte[]) in.readObject();

		TransactionHandler.sell(user, wine, price, qty, signature);
		out.writeUTF(
				String.format("%d unidade(s) de vinho %s colocada(s) a venda por %.2f com sucesso!", qty, wine, price));
	}

	/**
	 * Representa a funcao view
	 * 
	 * @param in  a stream de input
	 * @param out a stream de output
	 * @throws Exception
	 */
	private static void view(ObjectInputStream in, ObjectOutputStream out) throws Exception {
		String arg1 = in.readUTF();
		String[] result = ShowInfoHandler.view(arg1);
		out.writeBoolean(true);
		out.writeUTF(result[0]); // enviar printWine
		File img = new File(result[1]);
		out.writeUTF(img.getName());
		byte[] buffer = Files.readAllBytes(img.toPath());
		out.writeObject(buffer);
	}

	/**
	 * Representa a funcao buy
	 * 
	 * @param in   a stream de input
	 * @param out  a stream de output
	 * @param user o utilizador em questao
	 * @throws Exception
	 */
	private static void buy(ObjectInputStream in, ObjectOutputStream out, User user) throws Exception {
		String wine = in.readUTF();
		String seller = in.readUTF();
		int num = in.readInt();
		byte[] signature = (byte[]) in.readObject();

		TransactionHandler.buy(user, wine, seller, num, signature);
		out.writeUTF(String.format("O utilizador comprou %d unidades de vinho %s", num, wine));
	}

	/**
	 * Representa a funcao wallet
	 * 
	 * @param out  a stream de output
	 * @param user o utilizador em questao
	 * @throws Exception
	 */
	private static void wallet(ObjectOutputStream out, User user) throws Exception {
		out.writeUTF(ShowInfoHandler.wallet(user));
	}

	/**
	 * Representa a funcao classify
	 * 
	 * @param in   a stream de input
	 * @param out  a stream de output
	 * @param user o utilizador em questao
	 * @throws Exception
	 */
	private static void classify(ObjectInputStream in, ObjectOutputStream out, User user) throws Exception {
		String arg1 = in.readUTF();
		int num = Integer.parseInt(in.readUTF());
		AddInfoHandler.classify(user, arg1, num);
		out.writeUTF(String.format("Atribuiu %d estrelas ao vinho %s", num, arg1));
	}

	/**
	 * Representa a funcao talk
	 * 
	 * @param in   a stream de input
	 * @param out  a stream de output
	 * @param user o utilizador em questao
	 * @throws Exception
	 */
	private static void talk(ObjectInputStream in, ObjectOutputStream out, User user) throws Exception {
		String recipient = in.readUTF();
		String message = in.readUTF();
		AddInfoHandler.talk(user, recipient, message);
		out.writeUTF(String.format("Enviou uma mensagem ao utilizador %s", recipient));
	}

	/**
	 * Representa a funcao read
	 * 
	 * @param out  a stream de output
	 * @param user o utilizador em questao
	 * @throws Exception
	 */
	private static void read(ObjectOutputStream out, User user) throws Exception {
		out.writeUTF(ShowInfoHandler.read(user));
	}

	/**
	 * Representa a funcao list
	 * 
	 * @param out a stream de output
	 * @throws Exception
	 */
	private void list(ObjectOutputStream out) {
		try {
			out.writeUTF(ShowInfoHandler.list(blockChain));
		} catch (Exception e) {
			try {
				out.writeUTF(e.getMessage());
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		}
	}

}