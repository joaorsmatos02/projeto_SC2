package catalogs;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import entities.Transaction;
import exceptions.BlockChainException;
import utils.Utils;

public class BlockChain {

	private static BlockChain instance;
	private List<Block> blocks;
	private PublicKey serverPublicKey;
	private PrivateKey serverPrivateKey;

	private BlockChain() throws BlockChainException {
		this.blocks = new ArrayList<>();
	}

	public static BlockChain getInstance() throws BlockChainException {
		if (instance == null)
			instance = new BlockChain();
		return instance;
	}

	public void setKey(PublicKey pbk, PrivateKey pvk) {
		this.serverPublicKey = pbk;
		this.serverPrivateKey = pvk;
	}

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
				Block block2 = Block.readFromFile(new File("blockChain//block_2.blk"));
				// Block block3 = Block.readFromFile(new File("blockChain//block_3.blk"));
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

	public void addTransaction(Transaction ts) throws Exception {
		Block last = blocks.get(blocks.size() - 1);
		last.add(ts);
		if (last.isFull()) {
			signBlock(last);
			Block newBlock = new Block(blocks.size() + 1, last.generate32ByteHash());
			blocks.add(newBlock);
		}
	}

	private void signBlock(Block b) {
		byte[] toSign = b.generate32ByteHash();
		byte[] signed = Utils.signByteArray(serverPrivateKey, toSign);
		b.setSignature(signed);
	}

	public String listAllTransactions() {
		String result = "";
		for (Block b : blocks)
			result += b.toString() + "\r\n";
		return result;
	}

}
