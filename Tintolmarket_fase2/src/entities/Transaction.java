package entities;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public abstract class Transaction {
	private int transacaoId;
    private int vinhoId;
    private int unidades;
    private double valorUnidade;
    private int userId;
    private byte[] assinatura;

    public Transaction(int transacaoId, int vinhoId, int unidades, double valorUnidade, int userId, byte[] assinatura) {
        this.transacaoId = transacaoId;
        this.vinhoId = vinhoId;
        this.unidades = unidades;
        this.valorUnidade = valorUnidade;
        this.userId = userId;
        this.assinatura = assinatura;
    }

    public boolean verificarAssinatura(PublicKey chavePublica) {
        String m = String.format("%d%d%d%f%d", transacaoId, vinhoId, unidades, valorUnidade, userId);

        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(chavePublica);
            signature.update(m.getBytes(StandardCharsets.UTF_8));
            return signature.verify(assinatura);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
//    public byte[] assinar(PrivateKey privateKey) {
//        String m = String.format("%d%d%d%.2f%d", transacaoId, vinhoId, unidades, valorUnidade, userId);
//    	
//		try {
//			Signature signature = Signature.getInstance("SHA256withRSA");
//			signature.initSign(privateKey);
//			signature.update(m.getBytes(StandardCharsets.UTF_8));
//			assinatura = signature.sign();
//		} catch (InvalidKeyException e) {
//			System.out.println(e.getMessage());
//		} catch (SignatureException e) {
//			System.out.println(e.getMessage());
//		} catch (NoSuchAlgorithmException e) {
//			System.out.println(e.getMessage());
//		}
//		return assinatura;
//	}

    // Get & Set
	public int getTransacaoId() {
		return transacaoId;
	}

	public void setTransacaoId(int transacaoId) {
		this.transacaoId = transacaoId;
	}

	public int getVinhoId() {
		return vinhoId;
	}

	public void setVinhoId(int vinhoId) {
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

	public int getUserId() {
		return userId;
	}

	public void setUserId(int userId) {
		this.userId = userId;
	}

	public byte[] getAssinatura() {
		return assinatura;
	}

	public void setAssinatura(byte[] assinatura) {
		this.assinatura = assinatura;
	}    
}
