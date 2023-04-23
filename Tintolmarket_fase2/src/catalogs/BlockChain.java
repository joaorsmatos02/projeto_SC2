package catalogs;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import entities.Transaction;
import exceptions.BlockChainException;
import utils.Utils;

/**
 * 
 * A classe BlockChain representa a blockchain usada na aplicacao
 *
 */
public class BlockChain {

	private static BlockChain instance;
	private List<Block> blocks;
	private PublicKey serverPublicKey;
	private PrivateKey serverPrivateKey;

	/**
	 * Construtor privado da classe
	 */
	private BlockChain() {
		this.blocks = new ArrayList<>();
	}

	/**
	 * Getter estatico da classe
	 * 
	 * @return o objeto singleton da classe
	 */
	public static BlockChain getInstance() throws BlockChainException {
		if (instance == null)
			instance = new BlockChain();
		return instance;
	}

	/**
	 * Prepara as keys a serem usadas nas assinaturas da blockchain
	 * 
	 * @param pbk chave publica
	 * @param pvk chave privada
	 */
	public void setKey(PublicKey pbk, PrivateKey pvk) {
		this.serverPublicKey = pbk;
		this.serverPrivateKey = pvk;
	}

	/**
	 * Verifica a integridade da blockchain
	 * 
	 * @throws BlockChainException se ocorrer um erro na verificacao da blockchain
	 */
	public void verifyIntegrity() throws BlockChainException {
		try {
			File folder = new File("blockChain");
			if (!folder.exists())
				folder.mkdir();

			int blockNum = 1;
			File blockFile = new File("blockChain//block_1.blk");
			if (!blockFile.exists()) {
				Block a = new Block(1, new byte[32]);
				blocks.add(a);
			} else {
				Block block = Block.readFromFile(blockFile);
				if (block.isValid(serverPublicKey))
					blocks.add(block);
				else
					throw new BlockChainException("Erro ao recriar blockchain");

				while (block.isFull()) {
					blockNum++;
					block = Block.readFromFile(new File("blockChain//block_" + blockNum + ".blk"));
					if (block.isValid(serverPublicKey))
						blocks.add(block);
					else
						throw new BlockChainException("Erro ao recriar blockchain");
				}
			}

		} catch (BlockChainException e) {
			throw e;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Adiciona uma transacao a BlockChain
	 * 
	 * @param ts a transacao a adicionar
	 * @throws Exception
	 */
	public void addTransaction(Transaction ts) throws Exception {
		Block last = blocks.get(blocks.size() - 1);
		last.add(ts);
		if (last.isFull()) {
			signBlock(last);
			Block newBlock = new Block(blocks.size() + 1, last.generate32ByteHash());
			blocks.add(newBlock);
		}
	}

	/**
	 * Assina um bloco da blockchain
	 * 
	 * @param b o bloco a assinar
	 */
	private void signBlock(Block b) {
		byte[] toSign = b.generate32ByteHash();
		byte[] signed = Utils.signByteArray(serverPrivateKey, toSign);
		b.setSignature(signed);
	}

	/**
	 * Lista todas as transacoes presentes na blockchain
	 * 
	 * @return uma string com uma representacao textual das transacoes
	 * @throws BlockChainException 
	 */
	public String listAllTransactions() throws BlockChainException {
		verifyIntegrity();
		String result = "";
		for (Block b : blocks)
			result += b.toString();
		return result;
	}

}
