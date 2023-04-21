package entities;

import java.security.PrivateKey;

public class TransactionSell extends Transaction{

	public TransactionSell(int transacaoId, int vinhoId, int unidades, double valorUnidade, int userId,
			byte[] assinatura) {
		super(transacaoId, vinhoId, unidades, valorUnidade, userId, assinatura);
	}
}
