package entities;

public class TransactionSell extends Transaction {

	public TransactionSell(String vinhoId, int unidades, double valorUnidade, String userId, byte[] assinatura) {
		super(vinhoId, unidades, valorUnidade, userId, assinatura);
	}
}
