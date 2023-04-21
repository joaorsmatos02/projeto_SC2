package entities;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;

import catalogs.UserCatalog;

public abstract class Transaction {

	private String wineID;
	private int units;
	private double unitValue;
	private String userId;
	private byte[] signature;

	public Transaction(String vinhoId, int unidades, double valorUnidade, String userId, byte[] assinatura) {
		this.wineID = vinhoId;
		this.units = unidades;
		this.unitValue = valorUnidade;
		this.userId = userId;
		this.signature = assinatura;
	}

	public boolean validateTransaction() {
		PublicKey key = UserCatalog.getInstance().getPublicKey(userId);
		String f = String.format("%s%d%.2f%s", wineID, units, unitValue, userId);

		try {
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initVerify(key);
			s.update(f.getBytes(StandardCharsets.UTF_8));
			return s.verify(signature);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	// Get & Set Acho que nao vamos usar

	public String getVinhoId() {
		return wineID;
	}

	public void setVinhoId(String vinhoId) {
		this.wineID = vinhoId;
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
