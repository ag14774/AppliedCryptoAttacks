import java.io.BufferedReader;
import java.io.PrintWriter;

public abstract class AbstractAttacker implements IAttacker {

	/* Move these to AbstractAttacker */
	protected BufferedReader target_out = null;
	protected PrintWriter target_in = null;
	protected int interactions;
	
	protected byte[] recovered_bytes;
	
	public AbstractAttacker(BufferedReader target_out, PrintWriter target_in) {
		this.target_out = target_out;
		this.target_in = target_in;
		this.interactions = 0;
	}
	
	/*This in abstract class*/
	@Override
	public String getRecoveredMaterial() {
		String s = "";
		for(byte b : this.recovered_bytes){
			s += String.format("%02X", b);
		}
		return s;
	}

	/*This is abstract class*/
	@Override
	public int getInteractions() {
		return interactions;
	}

	@Override
	abstract public void attack();

}
