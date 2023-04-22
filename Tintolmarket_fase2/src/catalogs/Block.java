package catalogs;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import entities.Transaction;
import exceptions.BlockChainException;
import utils.Utils;

public class Block {

	private File blockFile;
	private int num;
	private byte[] previousHash;
	private Transaction[] transactions;
	private byte[] signature;

	public Block(File blockFile, int num, byte[] previousHash) {
		this.blockFile = blockFile;
		this.num = num;
		this.previousHash = previousHash;
		this.transactions = new Transaction[5];
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

	private void save() throws IOException {
		FileOutputStream fileOut = new FileOutputStream(blockFile);
		ObjectOutputStream objOut = new ObjectOutputStream(fileOut);
		objOut.writeObject(this);
		objOut.close();
		fileOut.close();
	}

	public boolean isFull() {
		return transactions[4] != null;
	}

	public void setSignature(byte[] s) {
		this.signature = s;
	}

	public boolean isValid(PublicKey pk) throws BlockChainException {
		boolean result = true;
		if (previousHash != new byte[32]) {
			Block prev = readFromFile(new File("blockChain//block_" + (num - 1) + ".blk"));
			result = prev.generate32ByteHash() == previousHash;
		}
		if (result && isFull()) {
			result = Utils.verifySignature(pk, generate32ByteHash(), signature);
		}
		return result;
	}

	public void add(Transaction ts) throws Exception {
		for (int i = 0; i < transactions.length; i++)
			if (transactions[i] == null) {
				transactions[i] = ts;
				break;
			}
		save();
	}

	public byte[] generate32ByteHash() {
		return previousHash;
	}

	public String toString() {
		String result = "";
		for (Transaction t : transactions)
			result += t.toString() + "\r\n";
		return result;
	}

}
