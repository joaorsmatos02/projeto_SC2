package entities;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;

import catalogs.UserCatalog;

public class Transaction {

	private String wineId;
	private int units;
	private double unitValue;
	private String userId;
	private byte[] signature;

	public Transaction(String vinhoId, int unidades, double valorUnidade, String userId, byte[] assinatura) {
		this.wineId = vinhoId;
		this.units = unidades;
		this.unitValue = valorUnidade;
		this.userId = userId;
		this.signature = assinatura;
	}

	public boolean validateTransaction() {
		PublicKey key = UserCatalog.getInstance().getPublicKey(userId);
		String f = String.format("%s%d%.2f%s", wineId, units, unitValue, userId);

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

	public String toString() {
		return wineId + "\r\n" + units + "\r\n" + unitValue + "\r\n" + userId + "\r\n" + signature + "\r\n";
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
