package entities;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import catalogs.UserCatalog;
import utils.Utils;

/**
 * 
 * A classe Transaction representa uma transacao buy ou sell
 *
 */
public class Transaction implements Serializable {

	/**
	 * A seed usada na serializacao dos objetos
	 */
	private static final long serialVersionUID = 6072210053516028044L;

	/**
	 * false indica uma operacao sell e true indica buy
	 */
	private boolean type;
	private String wineId;
	private int units;
	private double unitValue;
	private String userId;
	private byte[] signature;

	/**
	 * Construtor da classe
	 * 
	 * @param type      tipo de transacao, false indica uma operacao sell e true
	 *                  indica buy
	 * @param wineId    o vinho em questao
	 * @param units     o numero de unidades
	 * @param value     o valor de cada unidade
	 * @param userId    o utilizador
	 * @param signature assinatura do utilizador
	 */
	public Transaction(boolean type, String wineId, int units, double value, String userId, byte[] signature) {
		this.type = type;
		this.wineId = wineId;
		this.units = units;
		this.unitValue = value;
		this.userId = userId;
		this.signature = signature;
	}

	/**
	 * Valida uma transacao do tipo sell
	 * 
	 * @return true se transacao valida, false caso contratrio
	 */
	public boolean validateSellTransaction() {
		PublicKey key = UserCatalog.getInstance().getPublicKey(userId);
		String f = String.format("%s%d%.2f", wineId, units, unitValue);
		return Utils.verifySignature(key, f.getBytes(StandardCharsets.UTF_8), signature);
	}

	/**
	 * Valida uma transacao do tipo buy
	 * 
	 * @return true se transacao valida, false caso contratrio
	 */
	public boolean validateBuyTransaction() {
		PublicKey key = UserCatalog.getInstance().getPublicKey(userId);
		String f = String.format("%s%d%s", wineId, units, userId);
		return Utils.verifySignature(key, f.getBytes(StandardCharsets.UTF_8), signature);
	}

	@Override
	public String toString() {
		String s = null;
		if (type)
			s = "buy";
		else
			s = "sell";
		return "Operacao do tipo " + s + "\r\nVinho: " + wineId + "\r\nQuantidade: " + units + "\r\nValor: " + unitValue
				+ "\r\nUtilizador: " + userId + "\r\n";
	}

}
