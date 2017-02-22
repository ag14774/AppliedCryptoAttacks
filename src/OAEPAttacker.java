import java.io.*;

public class OAEPAttacker implements IAttacker {
	
	private BufferedReader target_out = null;
	private PrintWriter target_in = null;
	private int interactions;
	
	public OAEPAttacker(BufferedReader target_out, PrintWriter target_in) {
		this.target_out = target_out;
		this.target_in = target_in;
		this.interactions = 0;
	}
	
	private int interact(final String label, final String ciphertext) {
		target_in.println(label);
		target_in.println(ciphertext);
		
		int r = 0;
		try {
			r = Integer.parseInt(target_out.readLine());
		} catch (NumberFormatException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		interactions += 1;
		return r;
	}

	@Override
	public String getRecoveredMaterial() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getInteractions() {
		return interactions;
	}

	@Override
	public void attack() {
		int r = interact("43243244","4434");
		System.out.println(r);

	}

}
