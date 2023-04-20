package application;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.security.KeyStore;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import catalogs.UserCatalog;
import entities.User;
import exceptions.WineNotFoundException;
import exceptions.WrongCredentialsException;
import handlers.AddInfoHandler;
import handlers.ShowInfoHandler;
import handlers.TransactionHandler;

/**
 * Classe principal do servidor Tintolmarket.
 */
public class TintolmarketServer {

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

		////////////////////////////////////////////////////////////////////////////////
		//// TODO/////////////verificar integridade/criar blockchain////////////////////
		////////////////////////////////////////////////////////////////////////////////

		try {

			File file = new File(keyStorePath);
			FileInputStream is = new FileInputStream(file);
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(is, passwordKeystore.toCharArray());

			while (true) {
				SSLSocket socket = (SSLSocket) serverSocket.accept();
				ServerThread st = new ServerThread(socket, keyStore, filePassword);
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

}

/**
 * 
 * Classe ServerThread que representa uma thread para comunicacao com os
 * clientes.
 */
class ServerThread extends Thread {

	private SSLSocket socket;
	private KeyStore keyStore;
	private String filePassword;
	/////////////////////////////////////////////////////////
	// TODO Adicionar contador de blocos na blockchain?? ////
	/////////////////////////////////////////////////////////

	public ServerThread(SSLSocket inSoc, KeyStore keyStore, String filePassword) {
		this.socket = inSoc;
		this.keyStore = keyStore;
		this.filePassword = filePassword;
	}

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
			String name = userCatalog.login(in, out, keyStore);
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
				default:
					exit = true;
					break;
				}
				out.flush();
			} catch (WineNotFoundException e) {
				out.writeBoolean(false);
				out.writeUTF(e.getMessage());
				out.flush();
			} catch (Exception e) {
				out.writeUTF(e.getMessage());
				out.flush();
			}
		}
	}

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

	private static void sell(ObjectInputStream in, ObjectOutputStream out, User user) throws Exception {
		////////////////////////////////////////////////////////////////////////
		// TODO verificar assinatura do cliente e escrever na blockchain ///////
		////////////////////////////////////////////////////////////////////////
		String arg1 = in.readUTF();
		double price = Double.parseDouble(in.readUTF());
		int num = Integer.parseInt(in.readUTF());
		TransactionHandler.sell(user, arg1, price, num);
		out.writeUTF(String.format("%d quantidade(s) de vinho %s colocada(s) a venda por %.2f com sucesso!", num, arg1,
				price));
	}

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

	private static void buy(ObjectInputStream in, ObjectOutputStream out, User user) throws Exception {
		////////////////////////////////////////////////////////////////////////
		// TODO verificar assinatura do cliente e escrever na blockchain ///////
		////////////////////////////////////////////////////////////////////////
		String arg1 = in.readUTF();
		String arg2 = in.readUTF();
		int num = Integer.parseInt(in.readUTF());
		TransactionHandler.buy(user, arg1, arg2, num);
		out.writeUTF(String.format("O utilizador %s comprou %d unidades de vinho %s", arg2, num, arg1));
	}

	private static void wallet(ObjectOutputStream out, User user) throws Exception {
		out.writeUTF(ShowInfoHandler.wallet(user));
	}

	private static void classify(ObjectInputStream in, ObjectOutputStream out, User user) throws Exception {
		String arg1 = in.readUTF();
		int num = Integer.parseInt(in.readUTF());
		AddInfoHandler.classify(user, arg1, num);
		out.writeUTF(String.format("Atribuiu %d estrelas ao vinho %s", num, arg1));
	}

	private static void talk(ObjectInputStream in, ObjectOutputStream out, User user) throws Exception {
		String recipient = in.readUTF();
		String message = in.readUTF();
		AddInfoHandler.talk(user, recipient, message);
		out.writeUTF(String.format("Enviou uma mensagem ao utilizador %s", recipient));
	}

	private static void read(ObjectOutputStream out, User user) throws Exception {
		out.writeUTF(ShowInfoHandler.read(user));
	}

}