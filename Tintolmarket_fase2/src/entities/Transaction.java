package entities;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;

import catalogs.UserCatalog;

public abstract class Transaction {

	private String vinhoId;
	private int unidades;
	private double valorUnidade;
	private String userId;
	private byte[] assinatura;

	public Transaction(String vinhoId, int unidades, double valorUnidade, String userId, byte[] assinatura) {
		this.vinhoId = vinhoId;
		this.unidades = unidades;
		this.valorUnidade = valorUnidade;
		this.userId = userId;
		this.assinatura = assinatura;
	}

	public boolean verificarAssinatura(PublicKey chavePublica) {
		String s = String.format("%s%d%.2f%s", vinhoId, unidades, valorUnidade, userId);

		try {
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(chavePublica);
			signature.update(s.getBytes(StandardCharsets.UTF_8));
			return signature.verify(assinatura);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public boolean validateTransaction() {
		return verificarAssinatura(UserCatalog.getInstance().getPublicKey(userId));
	}

	// Get & Set Acho que nao vamos usar

	public String getVinhoId() {
		return vinhoId;
	}

	public void setVinhoId(String vinhoId) {
		this.vinhoId = vinhoId;
	}

	public int getUnidades() {
		return unidades;
	}

	public void setUnidades(int unidades) {
		this.unidades = unidades;
	}

	public double getValorUnidade() {
		return valorUnidade;
	}

	public void setValorUnidade(double valorUnidade) {
		this.valorUnidade = valorUnidade;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public byte[] getAssinatura() {
		return assinatura;
	}

	public void setAssinatura(byte[] assinatura) {
		this.assinatura = assinatura;
	}
}
