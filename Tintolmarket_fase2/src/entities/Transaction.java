package entities;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import catalogs.UserCatalog;
import utils.Utils;

public class Transaction implements Serializable {

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

	public Transaction(boolean type, String wineId, int units, double value, String userId, byte[] signature) {
		this.type = type;
		this.wineId = wineId;
		this.units = units;
		this.unitValue = value;
		this.userId = userId;
		this.signature = signature;
	}

	public boolean validateSellTransaction() {
		PublicKey key = UserCatalog.getInstance().getPublicKey(userId);
		String f = String.format("%s%d%.2f", wineId, units, unitValue);
		return Utils.verifySignature(key, f.getBytes(StandardCharsets.UTF_8), signature);
	}

	public boolean validateBuyTransaction() {
		PublicKey key = UserCatalog.getInstance().getPublicKey(userId);
		String f = String.format("%s%d%s", wineId, units, userId);
		return Utils.verifySignature(key, f.getBytes(StandardCharsets.UTF_8), signature);
	}

	public String toString() {
		String s = null;
		if (type)
			s = "buy";
		else
			s = "sell";
		return "Operacao do tipo " + s + "\r\nVinho: " + wineId + "\r\nQuantidade: " + units + "\r\nValor: " + unitValue
				+ "\r\nUtilizador: " + userId + "\r\n";
	}

	// Get & Set Acho que nao vamos usar

	public String getVinhoId() {
		return wineId;
	}

	public void setVinhoId(String vinhoId) {
		this.wineId = vinhoId;
	}

	public int getUnidades() {
		return units;
	}

	public void setUnidades(int unidades) {
		this.units = unidades;
	}

	public double getValorUnidade() {
		return unitValue;
	}

	public void setValorUnidade(double valorUnidade) {
		this.unitValue = valorUnidade;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public byte[] getAssinatura() {
		return signature;
	}

	public void setAssinatura(byte[] assinatura) {
		this.signature = assinatura;
	}
}
