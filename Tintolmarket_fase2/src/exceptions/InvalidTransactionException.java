package exceptions;

@SuppressWarnings("serial")
public class InvalidTransactionException extends Exception {
	public InvalidTransactionException(String msg) {
		super(msg);
	}
}
