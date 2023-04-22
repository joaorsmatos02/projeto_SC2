package handlers;

import java.util.List;

import catalogs.BlockChain;
import catalogs.UserCatalog;
import catalogs.WineAdCatalog;
import catalogs.WineCatalog;
import entities.Transaction;
import entities.User;
import entities.Wine;
import entities.WineAd;
import exceptions.NotEnoughBalanceException;
import exceptions.NotEnoughStockException;
import exceptions.UserNotFoundException;
import exceptions.WineNotFoundException;

/**
 * A classe TransactionHandler e responsavel por tratar das operacoes de compra
 * e venda de vinhos entre utilizadores.
 */
public class TransactionHandler {

	/**
	 * Cria um novo anuncio de vinho para venda.
	 * 
	 * @param user     O utilizador que deseja vender o vinho.
	 * @param wine     O nome do vinho a ser vendido.
	 * @param price    O preco unitario do vinho.
	 * @param quantity A quantidade disponivel para venda.
	 * @throws Exception
	 */
	public static void sell(User user, String wine, double price, int quantity, byte[] signature) throws Exception {
		Wine w = WineCatalog.getInstance().getWineByName(wine);
		if (w != null) {
			Transaction ts = new Transaction(false, wine, quantity, price, user.getName(), signature);
			if (ts.validateSellTransaction()) {
				user.createWineAd(w, price, quantity);
				BlockChain.getInstance().addTransaction(ts);
			}
		} else
			throw new WineNotFoundException("O vinho nao existe");
	}

	/**
	 * Realiza a compra de um vinho de um vendedor.
	 * 
	 * @param buyer     O utilizador que deseja comprar o vinho.
	 * @param wineName  O nome do vinho a ser comprado.
	 * @param seller    O nome do utilizador vendedor.
	 * @param quantity  A quantidade desejada para compra.
	 * @param signature A assinatura do clientes
	 * @throws NotEnoughStockException   Se nao houver stock suficiente.
	 * @throws UserNotFoundException     Se o utilizador nao for encontrado.
	 * @throws WineNotFoundException     Se o vinho nao for encontrado.
	 * @throws NotEnoughBalanceException Se nao tiver saldo suficiente.
	 */
	public static void buy(User buyer, String wineName, String seller, int quantity, byte[] signature)
			throws NotEnoughStockException, UserNotFoundException, WineNotFoundException, NotEnoughBalanceException {
		double balance = buyer.getBalance();

		User sellerUser = UserCatalog.getInstance().getUserByName(seller);
		if (sellerUser == null)
			throw new UserNotFoundException("O utilizador nao existe!");

		Wine wine = WineCatalog.getInstance().getWineByName(wineName);
		if (wine == null)
			throw new WineNotFoundException("O vinho nao existe!");

		WineAd wad = null;
		int availableQuantity = 0;
		double priceToPay = 0;
		List<WineAd> wineAds = wine.getCurrentAds();
		for (WineAd wa : wineAds) {
			if (wa.getUser().equals(sellerUser)) {
				wad = wa;
				availableQuantity = wa.getQuantity();
				priceToPay = wa.getPrice() * quantity;
				break;
			}
		}

		if (availableQuantity < quantity)
			throw new NotEnoughStockException("Nao existem unidades suficientes");
		if (priceToPay > balance)
			throw new NotEnoughBalanceException("Nao existe saldo suficiente");

		Transaction ts = new Transaction(true, wine.getName(), quantity, priceToPay / quantity, buyer.getName(),
				signature);

		try {
			if (ts.validateBuyTransaction()) {
				buyer.adjustBalance(-priceToPay);
				sellerUser.adjustBalance(priceToPay);
				wad.adjustQuantityAndPrice(-quantity, wad.getPrice());
				if (wad.getQuantity() == 0) {
					WineAdCatalog wineAdCatalog = WineAdCatalog.getInstance();
					wineAdCatalog.remove(wad);
				}
				BlockChain.getInstance().addTransaction(ts);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
}
