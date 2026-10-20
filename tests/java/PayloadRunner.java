import java.io.FileInputStream;
import java.io.ObjectInputStream;

public class PayloadRunner {
    public static void main(String[] args) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(args[0]))) {
            Object obj = ois.readObject();
            System.out.println("DESER_OK " + obj.getClass().getName());
        } catch (Throwable t) {
            System.out.println("DESER_FAIL " + t.getClass().getName() + ": " + t.getMessage());
            t.printStackTrace();
        }
    }
}
