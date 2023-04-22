package catalogs;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import entities.Transaction;
import exceptions.BlockChainException;
import utils.Utils;

public class Block implements Serializable {

	private static final long serialVersionUID = 7874046776398834019L;

	private byte[] previousHash;
	private int num;
	private int transactionCount;
	private Transaction[] transactions;
	private byte[] signature;

	public Block(int order, byte[] previousHash) {
		this.num = order;
		this.transactionCount = 0;
		this.previousHash = previousHash;
		this.transactions = new Transaction[5];
		save();
	}

	public boolean isFull() {
		return transactionCount == 5;
	}

	public void setSignature(byte[] s) {
		this.signature = s;
		save();
	}

	public boolean isValid(PublicKey pk) throws BlockChainException {
		boolean result = true;
		for (byte b : previousHash) {
			if (b != 0) {
				Block prev = readFromFile(new File("blockChain//block_" + (num - 1) + ".blk"));
				byte[] hash = prev.generate32ByteHash();
				for (int i = 0; i < hash.length; i++)
					if (hash[i] != previousHash[i])
						return false;

				break;
			}
		}
		if (result && isFull()) {
			result = Utils.verifySignature(pk, generate32ByteHash(), signature);
		}
		return result;
	}

	public void add(Transaction ts) throws Exception {
		if (!isFull()) {
			transactions[transactionCount] = ts;
			transactionCount++;
			save();
		}
	}

	public static Block readFromFile(File blockFile) throws BlockChainException {
		Block res = null;
		try {
			FileInputStream fileIn = new FileInputStream(blockFile);
			ObjectInputStream objIn = new ObjectInputStream(fileIn);
			res = (Block) objIn.readObject();
			objIn.close();
			fileIn.close();
		} catch (Exception e) {
			throw new BlockChainException("Erro ao ler blockchain");
		}
		return res;
	}

	private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
		previousHash = (byte[]) in.readObject();
		num = in.readInt();
		transactionCount = in.readInt();
		transactions = new Transaction[5];
		for (int i = 0; i < transactionCount; i++)
			transactions[i] = (Transaction) in.readObject();
		if (isFull())
			signature = (byte[]) in.readObject();
	}

	private void save() {
		try {
			File blockFile = new File("blockChain//block_" + num + ".blk");
			if (!blockFile.exists())
				blockFile.createNewFile();
			FileOutputStream fileOut = new FileOutputStream(blockFile);
			ObjectOutputStream objOut = new ObjectOutputStream(fileOut);
			objOut.writeObject(this);
			objOut.close();
			fileOut.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void writeObject(ObjectOutputStream out) throws IOException {
		out.writeObject(previousHash);
		out.writeInt(num);
		out.writeInt(transactionCount);
		for (int i = 0; i < transactionCount; i++)
			out.writeObject(transactions[i]);
		if (isFull())
			out.writeObject(signature);
	}

	/**
	 * Gera um hash de 32 bytes para o objeto atual. Este hash e usado para ser
	 * assinado pelo servidor, de forma a comprovar a autenticidade do bloco
	 * 
	 * @return um array com 32 bytes de hash
	 */
	public byte[] generate32ByteHash() {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(this.toString().getBytes());
			return hash; // nao pode considerar a assinatura anterior
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	public String toString() {
		String result = "";
		for (Transaction t : transactions)
			if (t != null)
				result += t.toString() + "\r\n";
			else
				break;
		return result;
	}

}
